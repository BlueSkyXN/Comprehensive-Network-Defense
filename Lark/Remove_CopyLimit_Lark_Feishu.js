// ==UserScript==
// @name         让你的飞书更好用(优化版)
// @license      GPL License
// @namespace    https://bytedance.com
// @version      0.3
// @description  让飞书文档不受权限限制，可以复制任意内容，可以打开右键菜单(复制下载图片)
// @author       NOABC
// @match        *://*.feishu.cn/*
// @match        *://*.larksuite.com/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=feishu.cn
// @grant        none
// @run-at       document-start
// @downloadURL https://update.greasyfork.org/scripts/473205/%E8%AE%A9%E4%BD%A0%E7%9A%84%E9%A3%9E%E4%B9%A6%E6%9B%B4%E5%A5%BD%E7%94%A8%28%E4%BC%98%E5%8C%96%E7%89%88%29.user.js
// @updateURL https://update.greasyfork.org/scripts/473205/%E8%AE%A9%E4%BD%A0%E7%9A%84%E9%A3%9E%E4%B9%A6%E6%9B%B4%E5%A5%BD%E7%94%A8%28%E4%BC%98%E5%8C%96%E7%89%88%29.meta.js
// ==/UserScript==
(function () {
  document.addEventListener('DOMContentLoaded', function () {
      const rawAddEventListener = document.addEventListener;
      document.addEventListener = function (type, listener, options) {
          if(type === 'copy') {
              rawAddEventListener.call(
                  document,
                  type,
                  event => {
                      return null;
                  },
                  options,
              );
              return
          }
          rawAddEventListener.call(
              document,
              type,
              listener,
              options,
          );
      };
      const bodyAddEventListener = document.body.addEventListener;
      document.body.addEventListener = function (type, listener, options) {
          bodyAddEventListener.call(
              document.body,
              type,
              event => {
                  if (type === 'contextmenu') {
                      return true;
                  }
                  return listener(event);
              },
              options,
          );
      };
  });

  XMLHttpRequest.prototype._open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (...args) {
      const [ method, url ] = args;
      if (method !== 'POST' || !url.includes('space/api/suite/permission/document/actions/state/')) {
          return this._open(...args);
      }

      this.addEventListener("readystatechange", function() {
          if (this.readyState !== 4) return;
          let response = this.response;
          try {
              response = JSON.parse(response);
          } catch(e) {};
          console.log('debug:', response);
          if (response.data.actions.copy === 1) {
              return;
          }

          response.data.actions.copy = 1;

          Object.defineProperty(this, 'response', {
              get() {
                  return response;
              }
          });
          Object.defineProperty(this, 'responseText', {
              get() {
                  return JSON.stringify(response);
              }
          });
      }, false);

      return this._open(...args);
  };
})();