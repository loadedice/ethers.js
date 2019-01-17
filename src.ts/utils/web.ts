'use strict';

import { XMLHttpRequest } from 'xmlhttprequest';

import { encode as base64Encode } from './base64';
import { shallowCopy } from './properties';
import { toUtf8Bytes } from './utf8';

import * as errors from '../errors';

// Exported Types
export interface ConnectionInfo {
    url: string;
    user?: string;
    password?: string;
    allowInsecure?: boolean;
    timeout?: number;
    headers?: { [key: string]: string | number };
}

export interface OnceBlockable {
    once(eventName: 'block', handler: () => void): void;
}

export interface PollOptions {
    timeout?: number;
    floor?: number;
    ceiling?: number;
    interval?: number;
    onceBlock?: OnceBlockable;
}

interface Header { key: string; value: string; }

export function fetchJson(connection: string | ConnectionInfo, json: string, processFunc: (value: any) => any): Promise<any> {
    const headers: { [key: string]: Header } = { };

    let url: string = null;

    let timeout = 2 * 60 * 1000;

    if (typeof(connection) === 'string') {
        url = connection;

    } else if (typeof(connection) === 'object') {
        if (connection.url == null) {
            errors.throwError('missing URL', errors.MISSING_ARGUMENT, { arg: 'url' });
        }

        url = connection.url;

        if (typeof(connection.timeout) === 'number' && connection.timeout > 0) {
            timeout = connection.timeout;
        }

        if (connection.headers) {
            for (const key in connection.headers) {
                headers[key.toLowerCase()] = { key, value: String(connection.headers[key]) };
            }
        }

        if (connection.user != null && connection.password != null) {
            if (url.substring(0, 6) !== 'https:' && connection.allowInsecure !== true) {
                errors.throwError(
                    'basic authentication requires a secure https url',
                    errors.INVALID_ARGUMENT,
                    { arg: 'url', url, user: connection.user, password: '[REDACTED]' },
                );
            }

            const authorization = connection.user + ':' + connection.password;
            headers.authorization = {
                key: 'Authorization',
                value: 'Basic ' + base64Encode(toUtf8Bytes(authorization)),
            };
        }
    }

    return new Promise((resolve, reject) => {
        const request = new XMLHttpRequest();

        let timer: any = null;
        timer = setTimeout(() => {
            if (timer == null) { return; }
            timer = null;

            reject(new Error('timeout'));
            setTimeout(() => {
                request.abort();
            }, 0);
        }, timeout);

        const cancelTimeout = () => {
            if (timer == null) { return; }
            clearTimeout(timer);
            timer = null;
        };

        if (json) {
            request.open('POST', url, true);
            headers['content-type'] = { key: 'Content-Type', value: 'application/json' };
        } else {
            request.open('GET', url, true);
        }

        Object.keys(headers).forEach((key) => {
            const header = headers[key];
            request.setRequestHeader(header.key, header.value);
        });

        request.onreadystatechange = () => {
            if (request.readyState !== 4) { return; }

            if (request.status !== 200) {
                cancelTimeout();
                // @TODO: not any!
                const error: any = new Error('invalid response - ' + request.status);
                error.statusCode = request.status;
                if (request.responseText) {
                    error.responseText = request.responseText;
                }
                reject(error);
                return;
            }

            let result: any = null;
            try {
                result = JSON.parse(request.responseText);
            } catch (error) {
                cancelTimeout();
                // @TODO: not any!
                const jsonError: any = new Error('invalid json response');
                jsonError.orginialError = error;
                jsonError.responseText = request.responseText;
                if (json != null) {
                    jsonError.requestBody = json;
                }
                jsonError.url = url;
                reject(jsonError);
                return;
            }

            if (processFunc) {
                try {
                    result = processFunc(result);
                } catch (error) {
                    cancelTimeout();
                    error.url = url;
                    error.body = json;
                    error.responseText = request.responseText;
                    reject(error);
                    return;
                }
            }

            cancelTimeout();
            resolve(result);
        };

        request.onerror = (error) => {
            cancelTimeout();
            reject(error);
        };

        try {
            if (json != null) {
                request.send(json);
            } else {
                request.send();
            }

        } catch (error) {
            cancelTimeout();
            // @TODO: not any!
            const connectionError: any = new Error('connection error');
            connectionError.error = error;
            reject(connectionError);
        }
    });
}

export function poll(func: () => Promise<any>, options?: PollOptions): Promise<any> {
    if (!options) { options = {}; }
    options = shallowCopy(options);
    if (options.floor == null) { options.floor = 0; }
    if (options.ceiling == null) { options.ceiling = 10000; }
    if (options.interval == null) { options.interval = 250; }

    return new Promise(function(resolve, reject) {

        let timer: any = null;
        let done: boolean = false;

        // Returns true if cancel was successful. Unsuccessful cancel means we're already done.
        const cancel = (): boolean => {
            if (done) { return false; }
            done = true;
            if (timer) { clearTimeout(timer); }
            return true;
        };

        if (options.timeout) {
            timer = setTimeout(() => {
                if (cancel()) { reject(new Error('timeout')); }
            }, options.timeout);
        }

        let attempt = 0;
        function check() {
            return func().then(function(result) {

                // If we have a result, or are allowed null then we're done
                if (result !== undefined) {
                    if (cancel()) { resolve(result); }

                } else if (options.onceBlock) {
                    options.onceBlock.once('block', check);

                // Otherwise, exponential back-off (up to 10s) our next request
                } else if (!done) {
                    attempt++;

                    let timeout = options.interval * parseInt(String(Math.random() * Math.pow(2, attempt)));
                    if (timeout < options.floor) { timeout = options.floor; }
                    if (timeout > options.ceiling) { timeout = options.ceiling; }

                    setTimeout(check, timeout);
                }

                return null;
            }, function(error) {
                if (cancel()) { reject(error); }
            });
        }
        check();
    });
}
