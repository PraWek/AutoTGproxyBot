/* Proxy Bot — frontend */

// ── Темы: system / dark / light ──────────────────────────────────────────────
(function initTheme() {
  const saved = localStorage.getItem('theme') || 'system';
  document.documentElement.dataset.theme = saved;
})();

const _THEMES      = ['system', 'dark', 'light'];
const _THEME_ICONS = { system: '⚙️', dark: '🌙', light: '☀️' };
const _THEME_TIPS  = { system: 'Системная тема', dark: 'Тёмная тема', light: 'Светлая тема' };

function _applyTheme(t) {
  document.documentElement.dataset.theme = t;
  localStorage.setItem('theme', t);
  const btn = document.getElementById('theme-toggle');
  if (btn) { btn.textContent = _THEME_ICONS[t]; btn.title = _THEME_TIPS[t]; }
}

function _cycleTheme() {
  const cur  = localStorage.getItem('theme') || 'system';
  const next = _THEMES[(_THEMES.indexOf(cur) + 1) % _THEMES.length];
  _applyTheme(next);
}

function _injectThemeToggle() {
  if (document.getElementById('theme-toggle')) return;
  const badge = document.getElementById('user-badge');
  if (!badge) return;
  const btn = document.createElement('button');
  btn.id          = 'theme-toggle';
  btn.className   = 'theme-toggle-btn';
  const cur       = localStorage.getItem('theme') || 'system';
  btn.textContent = _THEME_ICONS[cur];
  btn.title       = _THEME_TIPS[cur];
  btn.onclick     = _cycleTheme;
  badge.parentElement.insertBefore(btn, badge);
}

let refreshTimer = null;
let pollTimer    = null;
let botUsername  = '';
let _checkRunning = false;
let findSkipIds = new Set();

// ── Фильтры прокси ────────────────────────────────────────────────────────────
let filterRegion = 'all';
let filterType   = 'all';
let filterSort   = 'recommended';

// ── Таймер (абсолютный, хранится в localStorage) ─────────────────────────────
const TIMER_KEY = 'proxyNextAt';

function setNextUpdateAt(secondsFromNow) {
  const ts = Date.now() + secondsFromNow * 1000;
  try { localStorage.setItem(TIMER_KEY, String(ts)); } catch {}
}

function getSecondsLeft() {
  try {
    const stored = parseInt(localStorage.getItem(TIMER_KEY) || '0', 10);
    if (!stored) return 0;
    return Math.max(0, Math.ceil((stored - Date.now()) / 1000));
  } catch { return 0; }
}

// ── Утилиты ───────────────────────────────────────────────────────────────────
const esc = s =>
  String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
           .replace(/>/g,'&gt;').replace(/"/g,'&quot;');

const APP_ROUTES = new Set(['/', '/login', '/register', '/app', '/account', '/subscribe', '/connect_proxy']);

function currentPath() {
  const path = window.location.pathname.replace(/\/+$/, '') || '/';
  return APP_ROUTES.has(path) ? path : '/';
}

function setPath(path, replace = false) {
  const normalized = path === '/' ? '/' : path.replace(/\/+$/, '');
  if (window.location.pathname !== normalized) {
    const method = replace ? 'replaceState' : 'pushState';
    window.history[method]({}, '', normalized);
  }
}

function navigateTo(path, replace = false) {
  setPath(path, replace);
  init();
}

function stopTimers() {
  clearInterval(refreshTimer);
  clearInterval(pollTimer);
  refreshTimer = pollTimer = null;
}

// ── Scroll-reveal animation ───────────────────────────────────────────────────
let _revealObserver = null;
function _initReveal() {
  if (_revealObserver) _revealObserver.disconnect();
  _revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.classList.add('visible');
        _revealObserver.unobserve(e.target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
  document.querySelectorAll('.reveal').forEach(el => {
    _revealObserver.observe(el);
  });
}

// ── Шаги ─────────────────────────────────────────────────────────────────────
function renderSteps(active) {
  const wrap = document.getElementById('steps-wrap');
  if (!wrap) return;
  if (active <= 1) { wrap.innerHTML = ''; return; }
  const labels = ['Вход','Тариф 0 ₽','Прокси'];
  let html = '<div class="steps-wrap"><div class="steps-row">';
  labels.forEach((label, i) => {
    const n   = i + 1;
    const cls = n < active ? 'done' : n === active ? 'active' : '';
    const num = n < active ? '✓' : n;
    html += '<div class="step ' + cls + '">'
          + '<div class="step-circle">' + num + '</div>'
          + '<div class="step-label">' + label + '</div>'
          + '</div>';
    if (i < labels.length - 1)
      html += '<div class="step-line ' + (n < active ? 'done' : '') + '"></div>';
  });
  html += '</div></div>';
  wrap.innerHTML = html;
}

// ── Бейдж пользователя ────────────────────────────────────────────────────────
function renderBadge(me) {
  const el = document.getElementById('user-badge');
  if (!el) return;
  if (!me?.authenticated) { el.innerHTML = ''; return; }
  const name = esc(me.account_login || me.username || me.first_name || 'Пользователь');
  const avatar = me.photo_url
    ? '<img class="badge-photo" src="' + esc(me.photo_url) + '" alt="">'
    : '<span class="badge-avatar">👤</span>';
  el.innerHTML =
    '<div class="user-badge">'
    + '<button class="user-badge-btn" type="button" onclick="navigateTo(\'/account\')" title="Настройки аккаунта">'
    + avatar
    + '<span class="badge-name">' + name + '</span>'
    + '</button>'
    + '<a class="logout-btn" href="/logout">Выйти</a>'
    + '</div>';
}

function updateHeaderLogoLink(me) {
  const link = document.getElementById('header-logo-link');
  if (!link) return;
  const target = me?.authenticated ? '/connect_proxy' : '/';
  link.href = target;
  link.setAttribute(
    'aria-label',
    me?.authenticated ? 'Auto Proxy — к панели прокси' : 'Auto Proxy — на главную',
  );
}

// ── Шаг 1: Лендинг + Вход / Регистрация ──────────────────────────────────────
function renderLogin() {
  stopTimers();
  renderSteps(1);

  const botUrl    = botUsername ? 'https://t.me/' + botUsername : 'https://t.me/autotgproxysuperbot';
  const botHandle = botUsername ? ('@' + botUsername) : '@autotgproxysuperbot';

  const html = [
    '<div class="landing-page">',

    // ═══ HERO — простым языком ═══
    '<section class="hero-section">',
      '<div class="hero-bg">',
        '<div class="hero-orb hero-orb-1"></div>',
        '<div class="hero-orb hero-orb-2"></div>',
        '<div class="hero-orb hero-orb-3"></div>',
        '<div class="hero-grid"></div>',
      '</div>',
      '<div class="hero-content">',
        '<div class="hero-badge"><span class="hero-badge-dot"></span>',
        'Только для Telegram · Подключение одной кнопкой · Без изменения настроек системы</div>',
        '<h1 class="hero-title">',
          '<span class="hero-title-main">Поможем Telegram снова подключиться</span>',
          '<span class="hero-title-accent">Без сложных настроек</span>',
        '</h1>',
        '<p class="hero-subtitle">Если Telegram не открывается или долго загружает сообщения, нажмите одну кнопку. Сервис предложит подходящий сервер и откроет его в Telegram.</p>',
        '<div class="hero-cta-group">',
          '<div class="hero-cta-buttons">',
            '<a class="btn-hero-primary" href="' + esc(botUrl) + '" target="_blank" rel="noopener">',
              '✈️ Открыть бота в Telegram',
            '</a>',
            '<button class="btn-hero-secondary" onclick="navigateTo(\'/login\')">',
              'Продолжить на сайте →',
            '</button>',
          '</div>',
          '<p class="hero-note">Бесплатный доступ · 0 ₽ · Без карты</p>',
        '</div>',
        '<div class="hero-stats">',
          '<div class="stat-chip"><span class="stat-num">1 кнопка</span><span class="stat-label">для подключения</span></div>',
          '<div class="stat-chip"><span class="stat-num">24/7</span><span class="stat-label">проверка серверов</span></div>',
          '<div class="stat-chip"><span class="stat-num">3 мин</span><span class="stat-label">автообновление списка</span></div>',
          '<div class="stat-chip"><span class="stat-num">0</span><span class="stat-label">лишних настроек</span></div>',
        '</div>',
      '</div>',
    '</section>',

    // ═══ КАК ЭТО РАБОТАЕТ ═══
    '<div class="how-section">',
      '<div class="section">',
        '<h2 class="section-title section-center reveal">Инструкция по настройке</h2>',
        '<div class="how-steps">',
          '<div class="how-step reveal">',
            '<div class="how-num">1</div>',
            '<div class="how-step-title">Откройте бота или продолжите на сайте</div>',
            '<div class="how-step-desc">Нажмите кнопку «Открыть бота в Telegram» или нажмите «Продолжить на сайте»</div>',
          '</div>',
          '<div class="how-step reveal">',
            '<div class="how-num">2</div>',
            '<div class="how-step-title">Зарегистрируйтесь или войдите в аккаунт</div>',
            '<div class="how-step-desc">В боте Telegram аккаунт создаётся автоматически</div>',
          '</div>',
          '<div class="how-step reveal">',
            '<div class="how-num">3</div>',
            '<div class="how-step-title">Подтвердите тариф 0 ₽</div>',
            '<div class="how-step-desc">Никаких переводов, карт и внешних платёжных страниц</div>',
          '</div>',
          '<div class="how-step reveal">',
            '<div class="how-num">4</div>',
            '<div class="how-step-title">Нажмите «Подобрать прокси»</div>',
            '<div class="how-step-desc">Сервис предложит недавно проверенный сервер. Нажмите на ссылку и подтвердите подключение в Telegram</div>',
          '</div>',
          '<div class="how-step reveal">',
            '<div class="how-num">5</div>',
            '<div class="how-step-title">Пользуйтесь</div>',
            '<div class="how-step-desc">Используйте актуальную версию официального Telegram. Если он не подключился, вернитесь и нажмите «Не работает»</div>',
          '</div>',
        '</div>',
      '</div>',
    '</div>',

    // ═══ БЕЗ И С ═══
    '<div class="why-section">',
      '<div class="why-grid">',
        '<div class="why-col reveal">',
          '<div class="why-label why-label-bad">❌ Без сервиса</div>',
          '<h3 class="why-col-title">Telegram работает кое-как</h3>',
          '<div class="why-items">',
            '<div class="why-item"><span class="why-item-icon">📵</span><span>Сообщения долго отправляются или приложение не подключается</span></div>',
            '<div class="why-item"><span class="why-item-icon">🐌</span><span>Фото и видео грузятся по несколько минут</span></div>',
            '<div class="why-item"><span class="why-item-icon">🌐</span><span>VPN включен — но тормозит весь интернет</span></div>',
            '<div class="why-item"><span class="why-item-icon">😤</span><span>Каждый раз нужно искать рабочий прокси вручную</span></div>',
            '<div class="why-item"><span class="why-item-icon">🚫</span><span>Очередная волна блокировок протоколов и VPN перестаёт работать</span></div>',
          '</div>',
        '</div>',
        '<div class="why-col reveal">',
          '<div class="why-label why-label-good">✅ С нашим сервисом</div>',
          '<h3 class="why-col-title">Подключение за несколько нажатий</h3>',
          '<div class="why-items">',
            '<div class="why-item"><span class="why-item-icon">✅</span><span>Дополнительный маршрут подключения для сообщений и медиа</span></div>',
            '<div class="why-item"><span class="why-item-icon">⚡</span><span>Сначала показываются варианты с хорошими оценками пользователей</span></div>',
            '<div class="why-item"><span class="why-item-icon">🎯</span><span>Только Telegram — всё остальное не затронуто</span></div>',
            '<div class="why-item"><span class="why-item-icon">🔄</span><span>Не нужно ничего искать — система делает всё сама</span></div>',
            '<div class="why-item"><span class="why-item-icon">🛡️</span><span>Неработающие адреса исключаются</span></div>',
          '</div>',
        '</div>',
      '</div>',
    '</div>',

    // ═══ ТЕХНИЧЕСКИЙ БЛОК ═══
    '<div class="tech-section">',
      '<div class="section">',
        '<div class="tech-section-header reveal">',
          '<span class="tech-label">⚙️ Для тех, кто хочет знать больше</span>',
          '<h2 class="section-title">Система автоматического поиска рабочих прокси</h2>',
          '<p class="section-desc" style="margin-bottom:0">Технические подробности о том, как всё работает</p>',
        '</div>',
        '<div class="features-grid" style="margin-top:40px">',
          '<div class="feat-card reveal"><span class="feat-icon">🛡️</span>',
            '<div class="feat-title">Несколько способов подключения</div>',
            '<div class="feat-desc">Система распознаёт разные варианты MTProto, проверяет корректность ссылки и совместимость с Telegram. Детали реализации намеренно описаны абстрактно</div></div>',
          '<div class="feat-card reveal"><span class="feat-icon">🔍</span>',
            '<div class="feat-title">Адаптивная выдача</div>',
            '<div class="feat-desc">Учитываются свежесть проверки, медианная задержка, разброс результатов, тип транспорта и независимые жалобы пользователей</div></div>',
          '<div class="feat-card reveal"><span class="feat-icon">🌍</span>',
            '<div class="feat-title">Регионы RU и EU</div>',
            '<div class="feat-desc">Можно ограничить список российским или европейским регионом. Регион — один из факторов рекомендации, а не гарантия работы в конкретной сети</div></div>',
          '<div class="feat-card reveal"><span class="feat-icon">📊</span>',
            '<div class="feat-title">Две независимые оценки</div>',
            '<div class="feat-desc">Оценка сервера строится по техническим проверкам, а оценка пользователей — по подтверждениям «работает» и «не работает». Они не смешиваются в одну непонятную цифру</div></div>',
          '<div class="feat-card reveal"><span class="feat-icon">🔄</span>',
            '<div class="feat-title">Фоновая валидация</div>',
            '<div class="feat-desc">Источники обрабатываются параллельно, ответы ограничены по размеру, дубликаты удаляются, а нестабильные адреса уходят в карантин</div></div>',
          '<div class="feat-card reveal"><span class="feat-icon">⚙️</span>',
            '<div class="feat-title">Подключение одной кнопкой</div>',
            '<div class="feat-desc">Хост, порт и секрет передаются одной ссылкой. Рекомендуется актуальная версия официального Telegram</div></div>',
        '</div>',
      '</div>',
    '</div>',

    // ═══ ВИДЖЕТ ПОДДЕРЖКИ ═══
    '<div class="support-widget reveal">',
      '<span class="support-widget-icon">💬</span>',
      '<div class="support-widget-text">',
        '<span class="support-widget-title">Какие-то проблемы?</span>',
        '<span class="support-widget-desc">Напишите в поддержку: <b>autotgproxy@gmail.com</b></span>',
      '</div>',
    '</div>',

    // ═══ CTA БАННЕР ═══
    '<section class="cta-section">',
      '<div class="cta-banner reveal">',
        '<div class="cta-banner-content">',
          '<h2>Попробуйте прямо сейчас</h2>',
          '<p>Откройте бота в Telegram и получите недавно проверенный вариант.</p>',
          '<div class="cta-buttons-col">',
            '<a class="btn-cta-bot" href="' + esc(botUrl) + '" target="_blank" rel="noopener">',
              '✈️ Открыть ' + esc(botHandle) + ' в Telegram',
              '<span class="btn-cta-bot-sub">Быстрый старт · бесплатно</span>',
            '</a>',
            '<button class="btn-cta-site" onclick="navigateTo(\'/login\')">Продолжить на сайте →</button>',
          '</div>',
        '</div>',
      '</div>',
    '</section>',

    '</div>'
  ].join('');

  document.getElementById('content').innerHTML = html;
  _initReveal();
}

// ── Страница входа / регистрации ───────────────────────────────────────────────
function renderAuth(defaultTab) {
  stopTimers();
  renderSteps(1);
  const tab = defaultTab || (currentPath() === '/register' ? 'register' : 'login');
  const botUrl = botUsername ? 'https://t.me/' + botUsername : 'https://t.me/autotgproxysuperbot';

  const html = [
    '<section class="auth-section" id="auth-anchor">',
      '<button class="auth-back-btn" onclick="navigateTo(\'/\')">← Назад</button>',
      '<h2 class="auth-section-title">Личный кабинет</h2>',
      '<p class="auth-section-sub">Выбирайте и персонально подбирайте прокси через веб-интерфейс</p>',
      '<div class="auth-card fade-up">',
        '<div class="auth-tabs">',
          '<button class="auth-tab ' + (tab==='login'?'active':'') + '" id="tab-login" onclick="switchTab(\'login\')">Войти</button>',
          '<button class="auth-tab ' + (tab==='register'?'active':'') + '" id="tab-register" onclick="switchTab(\'register\')">Регистрация</button>',
        '</div>',
        '<div id="form-login" ' + (tab!=='login'?'style="display:none"':'') + '>',
          '<div class="form-group">',
            '<label for="login-login">Логин (ваш username в Telegram)</label>',
            '<input type="text" id="login-login" placeholder="username без @" autocomplete="username" spellcheck="false">',
            '<span class="form-hint">Ваш логин из аккаунта (или Telegram username без @). Нет аккаунта? Откройте вкладку «Регистрация».</span>',
          '</div>',
          '<div class="form-group">',
            '<label for="login-password">Пароль</label>',
            '<div class="pw-wrap">',
              '<input type="password" id="login-password" placeholder="Пароль" autocomplete="current-password">',
              '<button class="pw-eye" type="button" onclick="togglePw(\'login-password\',this)" tabindex="-1">👁</button>',
            '</div>',
          '</div>',
          '<div class="form-error" id="login-error"></div>',
          '<button class="btn btn-primary" id="login-btn" onclick="doLogin()">Войти в кабинет</button>',
        '</div>',
        '<div id="form-register" ' + (tab!=='register'?'style="display:none"':'') + '>',
          '<div class="form-group">',
            '<label for="reg-login">Логин (ваш username в Telegram)</label>',
            '<input type="text" id="reg-login" placeholder="username без @" autocomplete="username" spellcheck="false" maxlength="32">',
            '<span class="form-hint">Введите ваш Telegram username без @. Минимум 3 символа. Логин нельзя изменить.</span>',
          '</div>',
          '<div class="form-group">',
            '<label for="reg-password">Пароль</label>',
            '<div class="pw-wrap">',
              '<input type="password" id="reg-password" placeholder="Минимум 10 символов" autocomplete="new-password">',
              '<button class="pw-eye" type="button" onclick="togglePw(\'reg-password\',this)" tabindex="-1">👁</button>',
            '</div>',
          '</div>',
          '<div class="form-group">',
            '<label for="reg-password2">Повторите пароль</label>',
            '<div class="pw-wrap">',
              '<input type="password" id="reg-password2" placeholder="Повторите пароль" autocomplete="new-password">',
              '<button class="pw-eye" type="button" onclick="togglePw(\'reg-password2\',this)" tabindex="-1">👁</button>',
            '</div>',
          '</div>',
          '<div class="form-error" id="reg-error"></div>',
          '<button class="btn btn-primary" id="reg-btn" onclick="doRegister()">Создать аккаунт</button>',
        '</div>',
      '</div>',
    '</section>',
  ].join('');

  document.getElementById('content').innerHTML = html;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── Переключение вкладок ───────────────────────────────────────────────────────
function switchTab(tab) {
  const target = tab === 'register' ? '/register' : '/login';
  if (currentPath() !== target) {
    navigateTo(target);
    return;
  }
  document.getElementById('form-login').style.display    = tab === 'login'    ? '' : 'none';
  document.getElementById('form-register').style.display = tab === 'register' ? '' : 'none';
  document.getElementById('tab-login').classList.toggle('active',    tab === 'login');
  document.getElementById('tab-register').classList.toggle('active', tab === 'register');
}

// ── Показать/скрыть пароль ────────────────────────────────────────────────────
function togglePw(inputId, btn) {
  const inp = document.getElementById(inputId);
  if (!inp) return;
  if (inp.type === 'password') {
    inp.type = 'text';
    btn.textContent = '🙈';
  } else {
    inp.type = 'password';
    btn.textContent = '👁';
  }
}

// ── Вход ──────────────────────────────────────────────────────────────────────
async function doLogin() {
  const loginVal = (document.getElementById('login-login')?.value || '').trim();
  const passVal  = document.getElementById('login-password')?.value || '';
  const errEl    = document.getElementById('login-error');
  const btn      = document.getElementById('login-btn');

  if (!loginVal || !passVal) {
    if (errEl) errEl.textContent = 'Введите логин и пароль.';
    return;
  }

  btn.disabled    = true;
  btn.textContent = '⏳ Входим…';
  if (errEl) errEl.textContent = '';

  try {
    const res  = await fetch('/api/auth/login', {
      method:  'POST',
      headers: {'Content-Type': 'application/json'},
      body:    JSON.stringify({ login: loginVal, password: passVal }),
    });
    const data = await res.json();
    if (data.ok) {
      navigateTo('/subscribe', true);
    } else {
      if (errEl) errEl.textContent = data.error || 'Неверный логин или пароль.';
      btn.disabled    = false;
      btn.textContent = 'Войти в кабинет';
    }
  } catch {
    if (errEl) errEl.textContent = 'Ошибка сети. Попробуйте ещё раз.';
    btn.disabled    = false;
    btn.textContent = 'Войти в кабинет';
  }
}

// ── Регистрация ────────────────────────────────────────────────────────────────
async function doRegister() {
  const loginVal  = (document.getElementById('reg-login')?.value || '').trim();
  const passVal   = document.getElementById('reg-password')?.value || '';
  const pass2Val  = document.getElementById('reg-password2')?.value || '';
  const errEl     = document.getElementById('reg-error');
  const btn       = document.getElementById('reg-btn');

  if (errEl) errEl.textContent = '';

  if (!loginVal) { if (errEl) errEl.textContent = 'Введите логин.'; return; }
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(loginVal)) {
    if (errEl) errEl.textContent = 'Логин: 3–32 символа, только буквы a–z, цифры, _';
    return;
  }
  if (!passVal || passVal.length < 10) {
    if (errEl) errEl.textContent = 'Пароль должен быть не короче 10 символов.';
    return;
  }
  if (passVal !== pass2Val) {
    if (errEl) errEl.textContent = 'Пароли не совпадают.';
    return;
  }

  btn.disabled    = true;
  btn.textContent = '⏳ Создаём…';

  try {
    const res  = await fetch('/api/auth/register', {
      method:  'POST',
      headers: {'Content-Type': 'application/json'},
      body:    JSON.stringify({ login: loginVal, password: passVal }),
    });
    const data = await res.json();
    if (data.ok) {
      navigateTo('/subscribe', true);
    } else {
      if (errEl) errEl.textContent = data.error || 'Ошибка регистрации.';
      btn.disabled    = false;
      btn.textContent = 'Создать аккаунт';
    }
  } catch {
    if (errEl) errEl.textContent = 'Ошибка сети. Попробуйте ещё раз.';
    btn.disabled    = false;
    btn.textContent = 'Создать аккаунт';
  }
}

function renderAccountSettings(me) {
  stopTimers();
  renderSteps(1);

  const login = esc(me.account_login || me.username || 'не указан');
  const username = me.username ? '@' + esc(me.username) : 'не найден';
  const firstName = me.first_name ? esc(me.first_name) : 'не указано';
  const subText = 'бесплатный доступ · 0 ₽';
  const avatar = me.photo_url
    ? '<img class="account-avatar-img" src="' + esc(me.photo_url) + '" alt="">'
    : '<div class="account-avatar-fallback">👤</div>';

  document.getElementById('content').innerHTML = [
    '<div class="account-page">',
      '<div class="account-head fade-up">',
        '<button class="auth-back-btn" onclick="navigateTo(\'/connect_proxy\')">← К прокси</button>',
        '<h2 class="auth-section-title">Настройки аккаунта</h2>',
        '<p class="auth-section-sub">Здесь можно проверить данные входа и сменить пароль.</p>',
      '</div>',

      '<div class="account-card fade-up" style="animation-delay:.06s">',
        '<div class="account-profile-row">',
          avatar,
          '<div>',
            '<div class="account-login">' + login + '</div>',
            '<div class="account-muted">Логин совпадает с Telegram username. Если username в Telegram изменился, напишите в поддержку.</div>',
          '</div>',
        '</div>',
        '<div class="account-info-grid">',
          '<div class="account-info-item"><span>Telegram username</span><strong>' + username + '</strong></div>',
          '<div class="account-info-item"><span>Логин</span><strong>@' + login + '</strong></div>',
          '<div class="account-info-item"><span>Имя из Telegram</span><strong>' + firstName + '</strong></div>',
          '<div class="account-info-item"><span>Подписка</span><strong>' + subText + '</strong></div>',
        '</div>',
        '<div class="account-actions">',
          '<button class="btn btn-blue btn-inline" onclick="navigateTo(\'/connect_proxy\')">Открыть выбор прокси</button>',
          '<a class="btn btn-ghost btn-inline" href="/logout">Выйти из аккаунта</a>',
        '</div>',
      '</div>',

      '<div class="account-card fade-up" style="animation-delay:.1s">',
        '<h3 class="account-card-title">Сменить пароль</h3>',
        '<p class="account-muted">Новый пароль нужен только для входа на сайте. В Telegram-боте авторизация остаётся по вашему Telegram аккаунту.</p>',
        '<div class="form-group">',
          '<label for="old-password">Текущий пароль</label>',
          '<div class="pw-wrap">',
            '<input type="password" id="old-password" placeholder="Введите текущий пароль" autocomplete="current-password">',
            '<button class="pw-eye" type="button" onclick="togglePw(\'old-password\',this)" tabindex="-1">👁</button>',
          '</div>',
        '</div>',
        '<div class="form-group">',
          '<label for="new-password">Новый пароль</label>',
          '<div class="pw-wrap">',
            '<input type="password" id="new-password" placeholder="Минимум 10 символов" autocomplete="new-password">',
            '<button class="pw-eye" type="button" onclick="togglePw(\'new-password\',this)" tabindex="-1">👁</button>',
          '</div>',
        '</div>',
        '<div class="form-group">',
          '<label for="new-password2">Повторите новый пароль</label>',
          '<div class="pw-wrap">',
            '<input type="password" id="new-password2" placeholder="Повторите новый пароль" autocomplete="new-password">',
            '<button class="pw-eye" type="button" onclick="togglePw(\'new-password2\',this)" tabindex="-1">👁</button>',
          '</div>',
        '</div>',
        '<div class="form-error" id="account-password-msg"></div>',
        '<button class="btn btn-primary" id="account-password-btn" onclick="changeAccountPassword()">Сохранить новый пароль</button>',
      '</div>',
    '</div>',
  ].join('');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function changeAccountPassword() {
  const oldPassword = document.getElementById('old-password')?.value || '';
  const newPassword = document.getElementById('new-password')?.value || '';
  const newPassword2 = document.getElementById('new-password2')?.value || '';
  const msg = document.getElementById('account-password-msg');
  const btn = document.getElementById('account-password-btn');

  if (msg) {
    msg.textContent = '';
    msg.classList.remove('ok');
  }
  if (!oldPassword) { if (msg) msg.textContent = 'Введите текущий пароль.'; return; }
  if (!newPassword || newPassword.length < 10) { if (msg) msg.textContent = 'Новый пароль должен быть не короче 10 символов.'; return; }
  if (newPassword !== newPassword2) { if (msg) msg.textContent = 'Новые пароли не совпадают.'; return; }
  if (oldPassword === newPassword) { if (msg) msg.textContent = 'Новый пароль должен отличаться от текущего.'; return; }

  if (btn) { btn.disabled = true; btn.textContent = 'Сохраняю…'; }
  try {
    const res = await fetch('/api/account/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) throw new Error(data.error || 'Не удалось сменить пароль.');
    ['old-password', 'new-password', 'new-password2'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    if (msg) {
      msg.textContent = 'Пароль изменён. В следующий раз входите с новым паролем.';
      msg.classList.add('ok');
    }
  } catch (err) {
    if (msg) msg.textContent = err.message || 'Не удалось сменить пароль.';
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Сохранить новый пароль'; }
  }
}

function renderSubscribe() {
  renderSteps(2);
  document.getElementById('content').innerHTML = [
    '<div class="sub-page">',
      '<div class="sub-hero fade-up">',
        '<h2>Один шаг до стабильного Telegram</h2>',
        '<p>Доступ к автоматическому подбору и быстрой замене прокси</p>',
      '</div>',
      '<div class="card fade-up" style="animation-delay:.08s">',
        '<div class="plan-badge">⭐ Единственный тариф</div>',
        '<div class="price-block">',
          '<span class="price-amount">0</span>',
          '<div class="price-right">',
            '<span class="price-currency">₽</span>',
            '<span class="price-period">без списаний</span>',
          '</div>',
        '</div>',
        '<ul class="benefits">',
          '<li><span class="bi">🛡️</span><div><strong>Отбор подходящих серверов</strong><br><span class="ben-sub">Некорректные и явно недоступные варианты отсеиваются заранее</span></div></li>',
          '<li><span class="bi">🏆</span><div><strong>Топ‑10 лучших серверов</strong><br><span class="ben-sub">Только проверенные — медленные исключаются автоматически</span></div></li>',
          '<li><span class="bi">🔄</span><div><strong>Регулярное обновление</strong><br><span class="ben-sub">По умолчанию новый цикл запускается примерно каждые 3 минуты</span></div></li>',
          '<li><span class="bi">🤖</span><div><strong>Telegram-бот</strong><br><span class="ben-sub">Получайте прокси прямо в мессенджере</span></div></li>',
          '<li><span class="bi">⚡</span><div><strong>Сортировка по измерениям</strong><br><span class="ben-sub">Задержка и стабильность пересчитываются автоматически</span></div></li>',
        '</ul>',
        '<div class="trust-row">',
          '<span class="trust-item">✅ Бесплатный доступ</span>',
          '<span class="trust-item">🔒 Карта не нужна</span>',
        '</div>',
        '<div class="pay-methods">',
          '<button class="btn btn-sbp" onclick="navigateTo(\'/connect_proxy\')">',
            'Оплатить 0 ₽ — открыть прокси',
          '</button>',
        '</div>',
        '<p class="pay-note">Кнопка сразу переводит в панель. Деньги не списываются.</p>',
      '</div>',
    '</div>'
  ].join('');
}

// ── Шаг 3: Прокси ────────────────────────────────────────────────────────────
function renderActive(me) {
  renderSteps(3);
  const initSec = getSecondsLeft() || 150;

  document.getElementById('content').innerHTML = [
    '<div class="proxy-page">',
      '<div class="status-bar">',
        '<div class="status-left">',
          '<div class="green-dot"></div>',
          '<span>Обновление через&nbsp;<span id="countdown">' + initSec + '</span>&nbsp;с</span>',
        '</div>',
        '<span class="status-expires">доступ 0 ₽</span>',
      '</div>',

      '<div class="find-section fade-up">',
        '<p class="find-title">Найти прокси для вас</p>',
        '<p class="find-caveat">Учтём выбранные ниже фильтры, класс устройства и доступные браузеру параметры соединения. Содержимое трафика не читается.</p>',
        '<button class="btn find-btn" id="find-btn" onclick="findBestProxy(\'new\')">🔍 Найти прокси для вас</button>',
        '<div id="find-result"></div>',
      '</div>',

      '<div class="manual-divider fade-up" style="animation-delay:.08s"><span>Выбрать прокси вручную</span></div>',

      '<div class="filter-bar fade-up" style="animation-delay:.12s">',
        '<div class="filter-row">',
          '<div class="filter-group">',
            '<span class="filter-label">Регион</span>',
            '<div class="filter-pills">',
              '<button class="filter-pill ' + (filterRegion==='all'?'active':'') + '" onclick="setFilter(\'region\',\'all\',this)">Все</button>',
              '<button class="filter-pill ' + (filterRegion==='RU'?'active':'') + '" onclick="setFilter(\'region\',\'RU\',this)">🇷🇺 RU</button>',
              '<button class="filter-pill ' + (filterRegion==='EU'?'active':'') + '" onclick="setFilter(\'region\',\'EU\',this)">🇪🇺 EU</button>',
            '</div>',
          '</div>',
          '<div class="filter-group">',
            '<span class="filter-label">Тип</span>',
            '<div class="filter-pills">',
              '<button class="filter-pill ' + (filterType==='all'?'active':'') + '" onclick="setFilter(\'type\',\'all\',this)">Все</button>',
              '<button class="filter-pill ' + (filterType==='FakeTLS'?'active':'') + '" onclick="setFilter(\'type\',\'FakeTLS\',this)">Рекомендуемый</button>',
              '<button class="filter-pill ' + (filterType==='RandPad'?'active':'') + '" onclick="setFilter(\'type\',\'RandPad\',this)">Совместимый</button>',
              '<button class="filter-pill ' + (filterType==='Plain'?'active':'') + '" onclick="setFilter(\'type\',\'Plain\',this)">Обычный</button>',
            '</div>',
          '</div>',
        '</div>',
        '<div class="filter-row filter-sort-row">',
          '<span class="filter-label">Сортировка</span>',
          '<div class="filter-pills">',
            '<button class="filter-pill ' + (filterSort==='recommended'||filterSort==='user_rating'?'active':'') + '" onclick="setSort(\'user_rating\',this)">👥 Оценка пользователей</button>',
            '<button class="filter-pill ' + (filterSort==='server_rating'?'active':'') + '" onclick="setSort(\'server_rating\',this)">⭐ Оценка сервера</button>',
          '</div>',
          '<span class="filter-total" id="proxy-total"></span>',
        '</div>',
      '</div>',

      '<div id="proxy-list" class="fade-up" style="animation-delay:.18s">',
        '<div class="empty-state"><div class="eicon">⏳</div><p>Воркер проверяет серверы…<br>Список появится через минуту-две.</p></div>',
      '</div>',
    '</div>'
  ].join('');

  loadProxies();
  startCountdown();
}

// ── Таймер ────────────────────────────────────────────────────────────────────
function startCountdown() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    const left = getSecondsLeft();
    const el   = document.getElementById('countdown');
    if (el) el.textContent = left;
    if (left <= 0) {
      loadProxies();
    }
  }, 1000);
}

function setFilter(key, val, btn) {
  if (key === 'region') filterRegion = val;
  if (key === 'type')   filterType   = val;
  btn.parentElement.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  findSkipIds.clear();
  loadProxies();
}

function setSort(val, btn) {
  filterSort = val;
  btn.parentElement.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  findSkipIds.clear();
  loadProxies();
}

async function replaceProxy(proxyId) {
  const card = document.querySelector('.proxy-card[data-id="' + proxyId + '"]');
  if (card) {
    card.style.opacity = '0.4';
    card.style.pointerEvents = 'none';
  }
  try {
    const res  = await fetch('/api/proxies/replace', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        proxy_id: proxyId,
        region:   filterRegion,
        type:     filterType,
        sort:     filterSort,
      }),
    });
    const data = await res.json();
    if (data.ok && data.proxies) {
      const list = document.getElementById('proxy-list');
      if (list) list.innerHTML = data.proxies.map((p, i) => buildCard(p, i)).join('');
    } else {
      if (card) { card.style.opacity = '1'; card.style.pointerEvents = ''; }
    }
  } catch {
    if (card) { card.style.opacity = '1'; card.style.pointerEvents = ''; }
  }
}

// ── Прокси-карточки ───────────────────────────────────────────────────────────
async function reportProxyWorks(proxyId, btn) {
  if (!proxyId || !btn) return;
  btn.disabled = true;
  const oldText = btn.textContent;
  btn.textContent = 'Сохраняю…';
  try {
    const res = await fetch('/api/proxies/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: proxyId, outcome: 'works' }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || 'feedback_failed');
    btn.textContent = '✅ Спасибо, учтено';
  } catch {
    btn.disabled = false;
    btn.textContent = oldText;
  }
}

function tspuCls(v)  { return v >= 75 ? ['color-high','fill-high'] : v >= 45 ? ['color-mid','fill-mid'] : ['color-low','fill-low']; }
function pingCls(ms) { return ms <= 120 ? 'color-good' : ms <= 280 ? 'color-ok' : 'color-slow'; }

function buildCard(p, idx) {
  const quality  = p.transport_score ?? p.tspu ?? 0;
  const [tc, fc] = tspuCls(quality);
  const profile  = p.category === 'RU' ? 'Регион RU' : 'Регион EU';
  const stab     = p.stability ?? 100;
  const type     = p.type || 'Plain';
  const typeLabel = type === 'FakeTLS' ? 'Рекомендуемый' : type === 'RandPad' ? 'Совместимый' : 'Обычный';
  const rank     = idx + 1;
  const rankCls  = rank === 1 ? 'rank-gold' : rank === 2 ? 'rank-silver' : rank === 3 ? 'rank-bronze' : 'rank-default';
  const pingEmoji = p.ping <= 80 ? '🟢' : p.ping <= 200 ? '🟡' : '🔴';
  const typeColor = type === 'FakeTLS' ? 'badge-faketls' : type === 'RandPad' ? 'badge-randpad' : 'badge-plain';
  const pid      = esc(p.id || '');
  const ruScore  = Number.isFinite(Number(p.ru_reachability_score)) ? Number(p.ru_reachability_score) : 50;
  const ruTotal  = Number(p.ru_feedback_total || 0);
  const ruText   = ruTotal ? (ruScore + '/100 · ' + ruTotal + ' отзыв' + (ruTotal === 1 ? '' : 'ов')) : 'нет отзывов';
  const adminMark = p.admin_recommended ? '<span class="badge badge-admin">⭐ Выбор сервиса</span>' : '';
  const rankEmoji = rank === 1 ? '🥇' : rank === 2 ? '🥈' : rank === 3 ? '🥉' : '';
  return [
    '<div class="proxy-card" data-id="' + pid + '" data-server="' + esc(p.server) + '" data-port="' + p.port + '">',
      '<div class="card-row">',
        '<div class="proxy-rank ' + rankCls + '">' + (rank <= 3 ? rankEmoji : '#' + rank) + '</div>',
        '<div class="card-info">',
          '<div class="card-server">' + esc(p.server) + '</div>',
          '<div class="card-meta">' + profile + ' · Сервер ' + p.port + '</div>',
        '</div>',
        adminMark,
        '<span class="badge ' + typeColor + '">' + typeLabel + '</span>',
      '</div>',
      '<div class="metrics">',
        '<div class="metric">',
          '<span class="metric-label" title="Свежие ответы пользователей: работает или не работает">Оценка пользователей</span>',
          '<span class="metric-value ' + (ruScore>=65?'color-high':ruScore>=40?'color-mid':'color-low') + '">' + ruText + '</span>',
        '</div>',
        '<div class="metric">',
          '<span class="metric-label" title="Техническая проверка доступности сервера">Ответ сервера</span>',
          '<span class="metric-value ' + pingCls(p.ping) + '">' + pingEmoji + ' ' + p.ping + '&thinsp;мс</span>',
        '</div>',
        '<div class="metric metric-grow">',
          '<span class="metric-label" title="Итог технических проверок; не гарантирует работу у каждого оператора">Оценка сервера</span>',
          '<div class="tspu-wrap">',
            '<div class="tspu-bar"><div class="tspu-fill ' + fc + '" style="width:' + quality + '%"></div></div>',
            '<span class="metric-value ' + tc + '">' + quality + '/100</span>',
          '</div>',
        '</div>',
      '</div>',
      '<div class="card-actions">',
        '<a class="connect-btn" href="' + esc(p.tg_url) + '">',
          '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" style="flex-shrink:0">',
            '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8l-1.68 7.92c-.12.56-.44.7-.9.44l-2.5-1.84-1.2 1.16c-.13.13-.24.24-.5.24l.18-2.56 4.66-4.2c.2-.18-.04-.28-.32-.1L7.36 14.6 5 13.88c-.54-.17-.55-.54.12-.8l9.08-3.5c.44-.16.83.1.44.8z" fill="currentColor"/>',
          '</svg>',
          'Подключить в Telegram',
        '</a>',
        pid ? ('<button class="replace-btn" onclick="reportProxyWorks(\'' + pid + '\',this)">✅ Работает</button>') : '',
        pid ? ('<button class="replace-btn" onclick="replaceProxy(\'' + pid + '\')" title="Не работает — заменить">❌ Не работает</button>') : '',
      '</div>',
    '</div>'
  ].join('');
}

// ── Персональный подбор через профиль клиента и серверную проверку ───────────
function collectClientProfile() {
  const ua = navigator.userAgent || '';
  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection || {};
  let device = 'desktop';
  if (/iPad|Tablet/i.test(ua)) device = 'tablet';
  else if (/Android|iPhone|Mobile/i.test(ua) || navigator.maxTouchPoints > 2 && innerWidth < 900) device = 'mobile';
  const rawNetwork = String(connection.type || '').toLowerCase();
  const network = ['cellular', 'wifi', 'ethernet'].includes(rawNetwork) ? rawNetwork : 'unknown';
  return {
    device,
    network,
    effective_type: String(connection.effectiveType || 'unknown').toLowerCase(),
    rtt_ms: Number(connection.rtt || 0),
    downlink_mbps: Number(connection.downlink || 0),
    save_data: Boolean(connection.saveData),
    platform: String(navigator.userAgentData?.platform || navigator.platform || 'unknown').slice(0, 32),
  };
}

async function findBestProxy(mode = 'new', proxyId = '') {
  if (_checkRunning) return;
  _checkRunning = true;

  const btn      = document.getElementById('find-btn');
  const resultEl = document.getElementById('find-result');
  if (mode === 'new') findSkipIds.clear();
  if (proxyId) findSkipIds.add(proxyId);
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Подбираю…'; }
  if (resultEl) resultEl.innerHTML = '<p class="find-msg find-spin">🔍 Сопоставляю профиль и проверяю подходящие варианты…</p>';

  try {
    if (mode === 'failed' && proxyId) {
      await fetch('/api/proxies/ban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: proxyId }),
      });
    }

    const res = await fetch('/api/proxies/find-best', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        region: filterRegion,
        type: filterType,
        sort: filterSort,
        profile: collectClientProfile(),
        skip_ids: Array.from(findSkipIds),
      }),
    });
    if (res.status === 401) { init(); return; }
    const data = await res.json();

    if (data.ok && data.proxy) {
      const p = data.proxy;
      const quality = p.transport_score ?? p.tspu ?? 0;
      const ruTotal = Number(p.ru_feedback_total || 0);
      const ruScore = Number.isFinite(Number(p.ru_reachability_score)) ? Number(p.ru_reachability_score) : 50;
      const ruStatus = ruTotal ? (ruScore + '/100 по ' + ruTotal + ' свежим оценкам') : 'пока нет оценок';
      const adminStatus = p.admin_recommended ? '<br>⭐ Этот вариант рекомендован администратором' : '';
      const reasons = Array.isArray(p.match_reasons) ? p.match_reasons.map(esc).join(', ') : '';
      const reasonStatus = reasons ? '<br>🎯 Почему выбран: ' + reasons : '';
      const tgUrl = p.tg_url || ('tg://proxy?server=' + encodeURIComponent(p.server)
        + '&port=' + encodeURIComponent(p.port) + '&secret=' + encodeURIComponent(p.secret));
      findSkipIds.add(String(p.id));
      if (resultEl) resultEl.innerHTML = [
        '<div class="find-ok">',
        '<div class="find-ok-info">✅ <strong>' + esc(p.server) + ':' + p.port + '</strong><br>',
        'Профиль: ' + esc(data.profile_summary || 'технический профиль устройства') + '<br>',
        'Оценка пользователей: ' + ruStatus + '<br>Оценка сервера: ' + quality + '/100' + adminStatus + reasonStatus + '</div>',
        '<p class="find-caveat">Нажмите кнопку ниже и подтвердите подключение в Telegram. Только Telegram на вашем устройстве может окончательно показать, работает ли этот вариант в вашей сети.</p>',
        '<a class="find-connect-btn" href="' + esc(tgUrl) + '">🚀 Подключить в Telegram</a>',
        '<button class="find-retry-btn" onclick="reportProxyWorks(\'' + esc(p.id) + '\',this)">✅ Работает у меня</button>',
        '<button class="find-retry-btn" onclick="findBestProxy(\'next\',\'' + esc(p.id) + '\')">🔄 Найти другой</button>',
        '<button class="find-retry-btn" onclick="findBestProxy(\'failed\',\'' + esc(p.id) + '\')">❌ Не работает — учесть и заменить</button>',
        '</div>',
      ].join('');
    } else if (resultEl) {
      resultEl.innerHTML = '<div class="find-fail"><p>Сейчас нет недавно подтверждённых вариантов.</p>'
        + '<small>Подождите обновления списка или попробуйте ручной выбор ниже.</small>'
        + '<button class="find-retry-btn" onclick="findBestProxy(\'new\')">Проверить ещё раз</button></div>';
    }
  } catch {
    if (resultEl) resultEl.innerHTML = '<p class="find-msg find-err">Не удалось связаться с сервисом. Проверьте интернет и повторите.</p>';
  } finally {
    _checkRunning = false;
    if (btn) { btn.disabled = false; btn.textContent = '🔍 Найти прокси для вас'; }
  }
}

async function checkProxies() { return findBestProxy(); }

async function loadProxies() {
  const params = new URLSearchParams({
    region: filterRegion,
    type:   filterType,
    sort:   filterSort,
  });
  const res = await fetch('/api/proxies?' + params).catch(() => null);
  if (!res) return;
  if (res.status === 401) { init(); return; }
  const data = await res.json().catch(() => null);
  const list = document.getElementById('proxy-list');
  if (!list || !data) return;

  if (data.next_update_in != null) {
    const currentLeft = getSecondsLeft();
    if (currentLeft <= 0 || data.next_update_in < currentLeft) {
      setNextUpdateAt(data.next_update_in);
      const el = document.getElementById('countdown');
      if (el) el.textContent = data.next_update_in;
    }
  }

  const totalEl = document.getElementById('proxy-total');
  if (totalEl && data.total != null) {
    totalEl.textContent = data.total + ' прокси в базе';
  }

  if (!data.proxies?.length) {
    list.innerHTML = '<div class="empty-state"><div class="eicon">🔍</div>'
      + '<p>По выбранным фильтрам прокси не найдены.<br>Попробуйте изменить фильтры.</p></div>';
    return;
  }
  list.innerHTML = data.proxies.map((p, i) => buildCard(p, i)).join('');
}

// ── Точка входа ───────────────────────────────────────────────────────────────
async function init() {
  stopTimers();
  _injectThemeToggle();
  const path = currentPath();
  if (window.location.pathname !== path && APP_ROUTES.has(path)) setPath(path, true);

  document.getElementById('content').innerHTML =
    '<div class="spinner-wrap">⏳ Загрузка…</div>';

  try {
    const [cfg, me] = await Promise.all([
      fetch('/api/config').then(r => r.json()).catch(() => ({})),
      fetch('/api/me').then(r => r.json()).catch(() => ({})),
    ]);
    botUsername = cfg.bot_username || '';
    updateHeaderLogoLink(me);
    renderBadge(me);

    if (!me.authenticated) {
      if (path === '/login') {
        renderAuth('login');
      } else if (path === '/register') {
        renderAuth('register');
      } else if (path === '/app' || path === '/account' || path === '/subscribe' || path === '/connect_proxy') {
        setPath('/login', true);
        renderAuth('login');
      } else {
        renderLogin();
      }
      return;
    }

    if (path === '/login' || path === '/register' || path === '/') {
      setPath('/subscribe', true);
    }

    if (currentPath() === '/account') {
      renderAccountSettings(me);
    } else if (currentPath() === '/subscribe') {
      renderSubscribe();
    } else {
      if (currentPath() === '/app') setPath('/connect_proxy', true);
      renderActive(me);
    }
  } catch {
    document.getElementById('content').innerHTML =
      '<div class="empty-state"><div class="eicon">⚠️</div>'
      + '<p>Ошибка загрузки.<br>Обновите страницу.</p></div>';
  }
}

document.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    const active = document.activeElement?.id;
    if (active === 'login-login' || active === 'login-password') doLogin();
    if (active === 'reg-login' || active === 'reg-password' || active === 'reg-password2') doRegister();
    if (active === 'old-password' || active === 'new-password' || active === 'new-password2') changeAccountPassword();
  }
});

window.addEventListener('popstate', init);
document.addEventListener('DOMContentLoaded', () => { _injectThemeToggle(); init(); });
