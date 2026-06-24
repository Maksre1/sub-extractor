'use client';

import { useState, useEffect, useRef } from 'react';
import QRCode from 'qrcode';

export default function Home() {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [proxies, setProxies] = useState([]);
  const [toastMessage, setToastMessage] = useState('');
  
  // QR Modal States
  const [showQrModal, setShowQrModal] = useState(false);
  const [activeQrLink, setActiveQrLink] = useState('');
  const [activeQrName, setActiveQrName] = useState('');
  const canvasRef = useRef(null);

  // Ping States
  const [pings, setPings] = useState({});
  const [hwid, setHwid] = useState('');

  // Get or initialize client HWID
  useEffect(() => {
    let savedHwid = localStorage.getItem('sub_extractor_hwid');
    if (!savedHwid) {
      savedHwid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
      localStorage.setItem('sub_extractor_hwid', savedHwid);
    }
    setHwid(savedHwid);
  }, []);

  // Auto-hide toast after 2 seconds
  useEffect(() => {
    if (toastMessage) {
      const timer = setTimeout(() => setToastMessage(''), 2000);
      return () => clearTimeout(timer);
    }
  }, [toastMessage]);

  // Render QR code when modal opens and activeQrLink changes
  useEffect(() => {
    if (showQrModal && activeQrLink && canvasRef.current) {
      QRCode.toCanvas(
        canvasRef.current,
        activeQrLink,
        {
          width: 220,
          margin: 1,
          color: {
            dark: '#000000',
            light: '#ffffff',
          },
        },
        (err) => {
          if (err) console.error('Error generating QR:', err);
        }
      );
    }
  }, [showQrModal, activeQrLink]);

  const showToast = (message) => {
    setToastMessage(message);
  };

  const getEmoji = (name) => {
    const match = name.match(/[\uD83C-\uDBFF\uDC00-\uDFFF]+/);
    return match ? match[0] : '🌐';
  };

  const cleanProxyName = (name) => {
    let clean = name.replace(/[\uD83C-\uDBFF\uDC00-\uDFFF]+/g, '').trim();
    clean = clean.replace(/🚀/g, '').trim();
    return clean || 'Proxy';
  };

  const getProtocolBadgeClass = (proto) => {
    const p = proto.toLowerCase();
    if (p.includes('vless')) return 'badge-vless';
    if (p.includes('hysteria')) return 'badge-hysteria';
    return 'badge-other';
  };

  const handleExtract = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setIsLoading(true);
    setError('');
    setProxies([]);
    setPings({});

    try {
      const res = await fetch(`/api/parse?url=${encodeURIComponent(url.trim())}&hwid=${hwid}`);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Что-то пошло не так');
      }

      setProxies(data.proxies || []);
      showToast(`Успешно найдено ключей: ${data.proxies?.length || 0}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (link) => {
    navigator.clipboard.writeText(link);
    showToast('Ссылка скопирована в буфер обмена!');
  };

  const handleCopyAll = () => {
    if (proxies.length === 0) return;
    const allLinks = proxies.map(p => p.link).join('\n');
    navigator.clipboard.writeText(allLinks);
    showToast('Все ссылки скопированы в буфер обмена!');
  };

  const handlePing = async (idx, host, port) => {
    setPings(prev => ({ ...prev, [idx]: 'loading' }));
    try {
      const res = await fetch(`/api/ping?host=${encodeURIComponent(host)}&port=${port}`);
      const data = await res.json();
      if (res.ok && data.ping !== undefined) {
        setPings(prev => ({ ...prev, [idx]: data.ping }));
      } else {
        setPings(prev => ({ ...prev, [idx]: 'error' }));
      }
    } catch (err) {
      setPings(prev => ({ ...prev, [idx]: 'error' }));
    }
  };

  const handlePingAll = () => {
    if (proxies.length === 0) return;
    showToast('Запущен тест задержки для всех узлов...');
    proxies.forEach((p, idx) => {
      handlePing(idx, p.server, p.port);
    });
  };

  const openQr = (link, name) => {
    setActiveQrLink(link);
    setActiveQrName(name);
    setShowQrModal(true);
  };

  const getPingClass = (pingVal) => {
    if (typeof pingVal !== 'number') return '';
    if (pingVal < 100) return 'ping-good';
    if (pingVal < 250) return 'ping-medium';
    return 'ping-bad';
  };

  return (
    <div className="main-wrapper">
      <main className="app-container">
        <h1>SubExtractor</h1>
        <p className="subtitle">Удобный парсер VPN-подписок: вытаскивайте ключи VLESS и Hysteria2 в один клик</p>

        <div className="privacy-banner">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
          <span>Безопасно: ваши ссылки и ключи обрабатываются «на лету» в памяти, никуда не передаются и не сохраняются на сервере.</span>
        </div>

        <form onSubmit={handleExtract} className="input-group">
          <input
            type="text"
            className="input-field"
            placeholder="Вставьте ссылку (happ://add/https://... или incy://...)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={isLoading}
          />
          <button type="submit" className="btn-primary" disabled={isLoading || !url.trim()}>
            {isLoading ? (
              <>
                <div className="spinner"></div>
                Извлечение...
              </>
            ) : (
              'Получить ключи'
            )}
          </button>
        </form>

        {error && (
          <div className="alert-error">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="8" x2="12" y2="16"></line>
            </svg>
            <span>Ошибка: {error}</span>
          </div>
        )}

        {proxies.length > 0 && (
          <div>
            <div className="results-header">
              <div className="results-count">Найдено ключей: {proxies.length}</div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button onClick={handlePingAll} className="btn-copy-all">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                  </svg>
                  Тест пинга
                </button>
                <button onClick={handleCopyAll} className="btn-copy-all">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                  </svg>
                  Скопировать все
                </button>
              </div>
            </div>

            <div className="cards-list">
              {proxies.map((proxy, idx) => (
                <div key={idx} className="proxy-card">
                  <div className="card-top">
                    <div className="info-left">
                      <span className="country-flag">{getEmoji(proxy.name)}</span>
                      <span className="country-name">{cleanProxyName(proxy.name)}</span>
                      
                      {/* Latency display */}
                      {pings[idx] !== undefined && (
                        <span className={`ping-value ${getPingClass(pings[idx])}`}>
                          {pings[idx] === 'loading' ? (
                            '⚡ замер...'
                          ) : pings[idx] === 'error' ? (
                            '⚡ error'
                          ) : (
                            `⚡ ${pings[idx]} ms`
                          )}
                        </span>
                      )}
                    </div>
                    
                    <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                      <span className={`badge ${getProtocolBadgeClass(proxy.protocol)}`}>
                        {proxy.protocol}
                      </span>
                    </div>
                  </div>

                  <div className="server-info" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>Server: {proxy.server}:{proxy.port}</span>
                    <div className="card-actions">
                      <button 
                        onClick={() => handlePing(idx, proxy.server, proxy.port)} 
                        className="btn-action-text"
                        disabled={pings[idx] === 'loading'}
                      >
                        Пинг
                      </button>
                      <button onClick={() => openQr(proxy.link, proxy.name)} className="btn-action-text">
                        QR-код
                      </button>
                    </div>
                  </div>

                  <div className="uri-container">
                    <span className="uri-text">{proxy.link}</span>
                    <button
                      onClick={() => handleCopy(proxy.link)}
                      className="btn-copy"
                      title="Скопировать ключ"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                      </svg>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <section className="info-section">
          <h2 className="info-title">Поддерживаемые форматы</h2>
          <ul className="info-list">
            <li className="info-item">Ссылки приложений Happ, Incy, Hiddify, FoxTunnel, etc.</li>
            <li className="info-item">Стандартные V2Ray/Xray подписки в кодировке Base64</li>
            <li className="info-item">Сырые списки прокси-ссылок (vless://, hysteria2://, trojan://)</li>
          </ul>
        </section>
      </main>

      <footer className="app-footer">
        <a 
          href="https://github.com/Maksre1/sub-extractor" 
          target="_blank" 
          rel="noopener noreferrer" 
          className="github-link"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"></path>
          </svg>
          Открытый исходный код
        </a>
      </footer>

      {/* QR Code Modal Overlay */}
      {showQrModal && (
        <div className="modal-overlay" onClick={() => setShowQrModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3 className="modal-title">Сканировать QR-код</h3>
            <p className="modal-subtitle">{cleanProxyName(activeQrName)} ({activeQrLink.split('://')[0].toUpperCase()})</p>
            <div className="qr-wrapper">
              <canvas ref={canvasRef}></canvas>
            </div>
            <button className="btn-modal-close" onClick={() => setShowQrModal(false)}>
              Закрыть
            </button>
          </div>
        </div>
      )}

      {/* Floating toast notification */}
      {toastMessage && <div className="toast">{toastMessage}</div>}
    </div>
  );
}
