// ==UserScript==
// @name              移除飞书网页水印 | Remove watermarks of lark
// @description       移除飞书文档、工作台水印
// @name:zh-CN        移除飞书网页水印
// @description:zh-CN 移除飞书文档、工作台水印
// @name:en           Remove watermarks of lark
// @description:en    Remove watermarks from Lark documents and workspace.
// @version           0.7.1
// @license           The Unlicense
// @author            lbb00
// @homepage          https://github.com/lbb00/remove-feishu-watermark
// @match             https://*.feishu.cn/*
// @match             https://*.larksuite.com/*
// @run-at            document-start
// @grant             GM_addStyle
// @namespace https://greasyfork.org/users/793340
// @downloadURL https://update.greasyfork.org/scripts/459967/%E7%A7%BB%E9%99%A4%E9%A3%9E%E4%B9%A6%E7%BD%91%E9%A1%B5%E6%B0%B4%E5%8D%B0%20%7C%20Remove%20watermarks%20of%20lark.user.js
// @updateURL https://update.greasyfork.org/scripts/459967/%E7%A7%BB%E9%99%A4%E9%A3%9E%E4%B9%A6%E7%BD%91%E9%A1%B5%E6%B0%B4%E5%8D%B0%20%7C%20Remove%20watermarks%20of%20lark.meta.js
// ==/UserScript==

// GM_addStyle has removed from Greasemonkey v4.0
// https://groups.google.com/g/greasemonkey-users/c/KW71DL6Yjng
if (typeof GM_addStyle === 'undefined') {
    this.GM_addStyle = (aCss) => {
      'use strict'
      const head = document.getElementsByTagName('head')[0]
      if (head) {
        const style = document.createElement('style')
        style.setAttribute('type', 'text/css')
        style.textContent = aCss
        head.appendChild(style)
        return style
      }
      return null
    }
  }
  
  const bgImageNone = '{background-image: none !important;}'
  function genStyle(selector) {
    return `${selector}${bgImageNone}`
  }
  
  // global
  GM_addStyle(genStyle('[class*="watermark"]'))
  GM_addStyle(genStyle('[style*="pointer-events: none"]'))
  
  // 飞书文档
  GM_addStyle(genStyle('.ssrWaterMark'))
  GM_addStyle(genStyle('body>div>div>div>div[style*="position: fixed"]:not(:has(*))'))
  // firefox not support :has()
  GM_addStyle(genStyle('[class*="TIAWBFTROSIDWYKTTIAW"]'))
  
  // fixed for https://github.com/lbb00/remove-feishu-watermark/issues/3
  GM_addStyle(genStyle('body>div[style*="position: fixed"]:not(:has(*))')) // for readonly
  
  // 工作台
  GM_addStyle(genStyle('#watermark-cache-container'))
  GM_addStyle(genStyle('body>div[style*="inset: 0px;"]:not(:has(*))'))
  
  // Web 聊天
  GM_addStyle(genStyle('.chatMessages>div[style*="inset: 0px;"]'))
  