/*-
 * Copyright (c) 2013  Peter Pentchev
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * A naive implementation of a Promise-like interface.  For the moment,
 * it provides oncomplete(), onerror() and then() (one- or two-argument)
 * callbacks, as well as queueing any "complete" and "error" messages
 * until such time that a callback is actually defined.
 */

function openpgp_promise()
{
    this._pending_complete = [];
    this._pending_error = [];
    this._oncomplete_handler = null;
    this._onerror_handler = null;

    this._run_complete = function () {
	var i;

	if (this._oncomplete_handler == null || this._pending_complete.length == 0)
	    return;

        for (i = 0; i < this._pending_complete.length; i++)
	    this._oncomplete_handler(this._pending_complete[i]);
	this._pending_complete = [];
    }

    this._run_error = function () {
	var i;

	if (this._onerror_handler == null || this._pending_error.length == 0)
	    return;

        for (i = 0; i < this._pending_error.length; i++)
	    this._onerror_handler(this._pending_error[i]);
	this._pending_error = []
    }

    this._oncomplete = function (res) {
	this._pending_complete.push(res);
	this._run_complete();
    }

    this._onerror = function (res) {
	this._pending_error.push(res);
	this._run_error();
    }

    Object.defineProperty(this, 'oncomplete', {
	enumerable: true,
    	get: function get() { return this._oncomplete_handler; },
	set: function set(f) { this._oncomplete_handler = f; this._run_complete(); }
    });

    Object.defineProperty(this, 'onerror', {
	enumerable: true,
    	get: function get() { return this._onerror_handler; },
	set: function set(f) { this._onerror_handler = f; this._run_error(); }
    });

    this.then = function (resolve, reject) {
	this.oncomplete = resolve;
	if (reject != null)
	    this.onerror = reject;
    }
}
