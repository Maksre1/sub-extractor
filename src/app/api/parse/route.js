import { NextResponse } from 'next/server';

function cleanUrl(inputUrl) {
  let u = inputUrl.trim();
  
  // Strip leading/trailing quotes, spaces, and trailing question marks
  u = u.replace(/^["'\s]+|["'\s\?]+$/g, '');
  
  // Handle protocol prefixes (happ://add/, incy://import/, etc.)
  const schemaPrefixes = [
    /^happ:\/\/add\//i,
    /^happ:\/\/crypto\//i,
    /^incy:\/\/import\//i,
    /^hiddify:\/\/import\//i,
    /^clash:\/\/install-config\//i
  ];
  
  for (const pref of schemaPrefixes) {
    if (pref.test(u)) {
      u = u.replace(pref, '');
    }
  }
  
  // Handle nested HTTP/HTTPS redirect URLs
  try {
    const parsed = new URL(u);
    const nestedUrl = parsed.searchParams.get('url');
    if (nestedUrl) {
      return cleanUrl(nestedUrl);
    }
  } catch (e) {
    // Ignore URL parse error for now
  }
  
  return u;
}

function parseXrayOutbound(ob, remarks) {
  const protocol = ob.protocol;
  if (!protocol) return null;
  
  if (protocol === 'vless') {
    const vnext = ob.settings?.vnext?.[0];
    if (!vnext) return null;
    const addr = vnext.address;
    const port = vnext.port;
    const user = vnext.users?.[0];
    if (!user) return null;
    const uuid = user.id;
    const flow = user.flow || '';
    
    const ss = ob.streamSettings || {};
    const network = ss.network || 'tcp';
    const security = ss.security || 'none';
    
    const params = new URLSearchParams();
    params.set('type', network);
    if (security !== 'none') {
      params.set('security', security);
    }
    
    if (security === 'tls') {
      const tls = ss.tlsSettings || {};
      if (tls.serverName) params.set('sni', tls.serverName);
      if (tls.fingerprint) params.set('fp', tls.fingerprint);
    } else if (security === 'reality') {
      const reality = ss.realitySettings || {};
      if (reality.serverName) params.set('sni', reality.serverName);
      if (reality.publicKey) params.set('pbk', reality.publicKey);
      if (reality.shortId) params.set('sid', reality.shortId);
      if (reality.fingerprint) params.set('fp', reality.fingerprint);
    }
    
    if (flow) {
      params.set('flow', flow);
    }
    
    if (network === 'xhttp') {
      const xhttp = ss.xhttpSettings || {};
      if (xhttp.path) params.set('path', xhttp.path);
      if (xhttp.host) params.set('host', xhttp.host);
    }
    
    const query = params.toString();
    const link = `vless://${uuid}@${addr}:${port}?${query}#${remarks}`;
    return {
      name: remarks,
      protocol: 'VLESS',
      server: addr,
      port: port,
      link: link
    };
  } else if (protocol === 'hysteria') {
    const settings = ob.settings || {};
    const addr = settings.address;
    const port = settings.port;
    
    const ss = ob.streamSettings || {};
    const auth = ss.hysteriaSettings?.auth || '';
    const security = ss.security || 'tls';
    
    const params = new URLSearchParams();
    if (security === 'tls') {
      const tls = ss.tlsSettings || {};
      if (tls.serverName) params.set('sni', tls.serverName);
      if (tls.fingerprint) params.set('fp', tls.fingerprint);
      if (tls.alpn) params.set('alpn', tls.alpn.join(','));
    }
    
    const query = params.toString();
    const link = `hysteria2://${auth}@${addr}:${port}?${query}#${remarks}`;
    return {
      name: remarks,
      protocol: 'Hysteria2',
      server: addr,
      port: port,
      link: link
    };
  }
  
  return null;
}

function tryParseBase64(text) {
  try {
    const cleanText = text.replace(/\s/g, '');
    const decoded = Buffer.from(cleanText, 'base64').toString('utf-8');
    const lines = decoded.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const proxies = [];
    
    for (const line of lines) {
      if (/^(vless|vmess|ss|ssr|trojan|hysteria2|tuic):\/\//i.test(line)) {
        try {
          const url = new URL(line);
          const protocolName = url.protocol.replace(':', '').toUpperCase();
          const remarks = url.hash ? decodeURIComponent(url.hash.substring(1)) : 'Unnamed';
          const server = url.hostname;
          const port = url.port;
          proxies.push({
            name: remarks,
            protocol: protocolName,
            server: server,
            port: port,
            link: line
          });
        } catch (e) {
          proxies.push({
            name: 'Parsed Proxy',
            protocol: line.split('://')[0].toUpperCase(),
            server: 'N/A',
            port: 'N/A',
            link: line
          });
        }
      }
    }
    return proxies.length > 0 ? proxies : null;
  } catch (e) {
    return null;
  }
}

function tryParseRawLinks(text) {
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const proxies = [];
  
  for (const line of lines) {
    if (/^(vless|vmess|ss|ssr|trojan|hysteria2|tuic):\/\//i.test(line)) {
      try {
        const url = new URL(line);
        const protocolName = url.protocol.replace(':', '').toUpperCase();
        const remarks = url.hash ? decodeURIComponent(url.hash.substring(1)) : 'Unnamed';
        const server = url.hostname;
        const port = url.port;
        proxies.push({
          name: remarks,
          protocol: protocolName,
          server: server,
          port: port,
          link: line
        });
      } catch (e) {
        proxies.push({
          name: 'Parsed Proxy',
          protocol: line.split('://')[0].toUpperCase(),
          server: 'N/A',
          port: 'N/A',
          link: line
        });
      }
    }
  }
  return proxies.length > 0 ? proxies : null;
}

function isStubProxy(proxy) {
  if (!proxy) return false;
  const name = (proxy.name || '').toLowerCase();
  const server = (proxy.server || '');
  const link = (proxy.link || '').toLowerCase();
  
  if (server === '0.0.0.0' || server === '127.0.0.1' || proxy.port === 1 || proxy.port === '1') {
    return true;
  }
  
  if (name.includes('не поддерживает') || name.includes('скачайте') || name.includes('happ') || name.includes('limit')) {
    return true;
  }
  
  if (link.includes('00000000-0000-0000-0000-000000000000')) {
    return true;
  }
  
  return false;
}

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  let targetUrl = searchParams.get('url');
  const clientHwid = searchParams.get('hwid');
  
  if (!targetUrl) {
    return NextResponse.json({ error: 'Missing subscription url parameter' }, { status: 400 });
  }
  
  try {
    targetUrl = cleanUrl(targetUrl);
  } catch (e) {
    return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 });
  }
  
  // Try to fetch with different User-Agents
  const userAgents = ['Happ', 'Clash', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'];
  let fetchError = null;
  let responseText = '';
  let successfulUA = '';
  let isHwidEmptyBlock = false;
  
  for (const ua of userAgents) {
    try {
      const headers = { 'User-Agent': ua };
      if (clientHwid) {
        headers['X-Hwid'] = clientHwid;
        headers['X-Device-Os'] = 'iOS';
        headers['X-Device-Model'] = 'iPhone';
      }
      
      const response = await fetch(targetUrl, {
        headers: headers,
        next: { revalidate: 60 } // Cache for 60 seconds
      });
      
      if (response.ok) {
        responseText = await response.text();
        successfulUA = ua;
        if (responseText.trim() === '' && clientHwid) {
          isHwidEmptyBlock = true;
        } else {
          isHwidEmptyBlock = false;
        }
        break;
      } else {
        fetchError = `HTTP error! Status: ${response.status}`;
      }
    } catch (err) {
      fetchError = err.message;
    }
  }
  
  if (isHwidEmptyBlock) {
    return NextResponse.json({
      error: 'Эта подписка защищена привязкой к устройству (HWID). Пожалуйста, сбросьте привязку в Telegram-боте вашего VPN-провайдера (кнопка «Сбросить HWID / Привязку»), после чего обновите эту страницу.',
      hwidRequired: true
    }, { status: 403 });
  }
  
  if (!responseText) {
    return NextResponse.json({ error: `Failed to fetch subscription: ${fetchError}` }, { status: 502 });
  }
  
  let format = '';
  let parsedProxies = [];
  
  // Parsing flow
  // 1. Check if it is Happ JSON format (array of configurations)
  try {
    const jsonData = JSON.parse(responseText);
    if (Array.isArray(jsonData)) {
      const proxies = [];
      for (const item of jsonData) {
        if (item.outbounds && Array.isArray(item.outbounds)) {
          const remarks = item.remarks || 'Config';
          const p = parseXrayOutbound(item.outbounds[0], remarks);
          if (p) {
            proxies.push(p);
          }
        }
      }
      if (proxies.length > 0) {
        format = 'Happ JSON';
        parsedProxies = proxies;
      }
    }
  } catch (e) {
    // Not JSON, continue to other parsers
  }
  
  // 2. Check if it is Base64 subscription
  if (parsedProxies.length === 0) {
    const base64Proxies = tryParseBase64(responseText);
    if (base64Proxies) {
      format = 'Base64 List';
      parsedProxies = base64Proxies;
    }
  }
  
  // 3. Check if it is raw list of URIs
  if (parsedProxies.length === 0) {
    const rawProxies = tryParseRawLinks(responseText);
    if (rawProxies) {
      format = 'Raw Link List';
      parsedProxies = rawProxies;
    }
  }
  
  if (parsedProxies.length === 0) {
    return NextResponse.json({ error: 'Unable to recognize subscription format or no proxy keys found' }, { status: 422 });
  }
  
  // Filter out stub/warning proxies used by providers to display error messages
  const cleanProxies = [];
  let hasHwidWarning = false;
  
  for (const p of parsedProxies) {
    if (isStubProxy(p)) {
      hasHwidWarning = true;
    } else {
      cleanProxies.push(p);
    }
  }
  
  if (cleanProxies.length === 0 && hasHwidWarning) {
    return NextResponse.json({
      error: 'Эта подписка привязана к другому устройству или требует сброса. Пожалуйста, зайдите в Telegram-бот вашего VPN-провайдера, нажмите «Сбросить HWID / Привязку», а затем обновите эту страницу.',
      hwidRequired: true
    }, { status: 403 });
  }
  
  if (cleanProxies.length === 0) {
    return NextResponse.json({ error: 'Не найдено доступных VPN-ключей в этой подписке.' }, { status: 422 });
  }
  
  return NextResponse.json({ format, proxies: cleanProxies });
}
