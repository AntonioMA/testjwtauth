/* globals window,document, AuthHelper */
!(function() {

  'use strict'; // eslint-disable-line

  function addText(aElem, aText) {
    return aElem.appendChild(document.createTextNode(aText));
  }

  function createElement(aType, aAttrs, aOptionalText) {
    const elem = document.createElement(aType);

    // Add all the requested attributes
    if (aAttrs) {
      for (const i in aAttrs) { // eslint-disable-line no-restricted-syntax
        if (i.startsWith('data-')) {
          const dataElem = i.replace('data-', '');
          elem.data(dataElem, aAttrs[i]);
        } else {
          elem.setAttribute(i, aAttrs[i]);
        }
      }
    }

    if (aOptionalText) {
      addText(elem, aOptionalText);
    }

    return elem;
  }

  function createElementAt(aMainBody, aType, aAttrs, aOptionalText, aBefore) {
    const elem = createElement(aType, aAttrs, aOptionalText);

    if (!aBefore) {
      aMainBody.appendChild(elem);
    } else {
      aMainBody.insertBefore(elem, aBefore);
    }

    return elem;
  }

  const HTMLElems = {
    createElement,
    createElementAt,
  };


  window.addEventListener('load', () => {
    const outputUL = document.getElementById('output');
    const addEvtLog = msg => HTMLElems.createElementAt(outputUL, 'li', null, msg);

    document.getElementById('testButton').addEventListener('click', () => {
      addEvtLog('Getting Auth Token');
      AuthHelper.
        ensureAuth().
        then(token => addEvtLog('Auth Token: ' + token)).
        catch(e => addEvtLog('Error: ' + e.message));
    });

  });
}());
