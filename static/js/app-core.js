(function () {
  'use strict';

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const originalFetch = window.fetch.bind(window);

  window.fetch = function (input, init = {}) {
    const url = typeof input === 'string' ? input : input.url;
    const method = String(init.method || (typeof input !== 'string' && input.method) || 'GET').toUpperCase();
    if (csrf && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && new URL(url, location.href).origin === location.origin) {
      const headers = new Headers(init.headers || (typeof input !== 'string' ? input.headers : undefined));
      headers.set('X-CSRF-Token', csrf);
      init = { ...init, headers };
    }
    return originalFetch(input, init);
  };

  function injectCsrf() {
    if (!csrf) return;
    document.querySelectorAll('form').forEach((form) => {
      const method = String(form.method || 'get').toLowerCase();
      if (method !== 'post' || form.querySelector('input[name="_csrf_token"]')) return;
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = '_csrf_token';
      input.value = csrf;
      form.appendChild(input);
    });
  }

  window.appConfirm = function (message, options = {}) {
    const modalEl = document.getElementById('appConfirmModal');
    if (!modalEl || !window.bootstrap) return Promise.resolve(window.confirm(message));
    modalEl.querySelector('[data-confirm-title]').textContent = options.title || 'Confirmar operação';
    modalEl.querySelector('[data-confirm-message]').textContent = message || 'Deseja continuar?';
    const button = modalEl.querySelector('[data-confirm-action]');
    button.className = `btn ${options.danger ? 'btn-danger' : 'btn-primary'}`;
    button.innerHTML = options.danger
      ? '<i class="bi bi-exclamation-triangle me-1"></i>Confirmar'
      : '<i class="bi bi-check-lg me-1"></i>Confirmar';
    return new Promise((resolve) => {
      const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
      let resolved = false;
      const finish = (value) => {
        if (resolved) return;
        resolved = true;
        resolve(value);
      };
      button.onclick = () => {
        finish(true);
        modal.hide();
      };
      modalEl.addEventListener('hidden.bs.modal', () => finish(false), { once: true });
      modal.show();
    });
  };

  window.appAlert = function (message, options = {}) {
    const modalEl = document.getElementById('appAlertModal');
    if (!modalEl || !window.bootstrap) return;
    modalEl.querySelector('[data-alert-message]').textContent = message || 'Não foi possível concluir a operação.';
    const title = modalEl.querySelector('.modal-title');
    title.innerHTML = options.danger
      ? '<i class="bi bi-exclamation-octagon me-2 text-danger"></i>Não foi possível concluir'
      : '<i class="bi bi-info-circle me-2 text-primary"></i>Atenção';
    bootstrap.Modal.getOrCreateInstance(modalEl).show();
  };
  window.alert = (message) => window.appAlert(message);

  function upgradeConfirmForms() {
    document.querySelectorAll('form[onsubmit*="confirm("]').forEach((form) => {
      const source = form.getAttribute('onsubmit') || '';
      const match = source.match(/confirm\((['"])([\s\S]*?)\1\)/);
      if (!match) return;
      form.removeAttribute('onsubmit');
      form.dataset.confirm = match[2];
      if (/excluir|remover|revogar|estornar/i.test(match[2])) form.dataset.confirmDanger = '1';
    });

    document.addEventListener('submit', async (event) => {
      const form = event.target.closest('form[data-confirm]');
      if (!form || form.dataset.confirmed === '1') return;
      event.preventDefault();
      const accepted = await window.appConfirm(form.dataset.confirm, {
        danger: form.dataset.confirmDanger === '1'
      });
      if (accepted) {
        form.dataset.confirmed = '1';
        form.requestSubmit();
      }
    }, true);
  }

  document.addEventListener('DOMContentLoaded', () => {
    injectCsrf();
    upgradeConfirmForms();
    document.querySelectorAll('button[title], a[title]').forEach((element) => {
      if (!element.getAttribute('aria-label') && !element.textContent.trim()) {
        element.setAttribute('aria-label', element.getAttribute('title'));
      }
    });
    document.querySelectorAll('form').forEach((form) => {
      form.addEventListener('submit', (event) => {
        if (event.defaultPrevented) return;
        if (!form.checkValidity()) return;
        const button = form.querySelector('button[type="submit"], button:not([type])');
        if (!button || button.dataset.keepEnabled === '1') return;
        button.dataset.originalHtml = button.innerHTML;
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>Processando...';
      });
    });
  });
})();
