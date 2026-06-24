import { NextResponse } from 'next/server';
import net from 'net';

function testTcp(host, port, timeout = 1500) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    
    socket.setTimeout(timeout);
    
    socket.connect(port, host, () => {
      const delay = Date.now() - start;
      socket.destroy();
      resolve({ delay, status: 'open' });
    });
    
    socket.on('error', (err) => {
      const delay = Date.now() - start;
      socket.destroy();
      
      // Connection refused means the server is reachable and active, but port is closed on TCP
      if (err.code === 'ECONNREFUSED') {
        resolve({ delay, status: 'reachable' });
      } else {
        resolve({ error: err.message, status: 'failed' });
      }
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ error: 'timeout', status: 'timeout' });
    });
  });
}

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const host = searchParams.get('host');
  const portStr = searchParams.get('port');
  
  if (!host || !portStr) {
    return NextResponse.json({ error: 'Missing host or port parameters' }, { status: 400 });
  }
  
  const port = parseInt(portStr, 10);
  if (isNaN(port) || port <= 0 || port > 65535) {
    return NextResponse.json({ error: 'Invalid port' }, { status: 400 });
  }
  
  // 1. Try to connect to target port
  let result = await testTcp(host, port);
  
  // 2. If it failed or timed out (common for UDP-only services like Hysteria2),
  // try to connect to standard SSH (22) or Web (80) ports on the same host to measure RTT.
  if (result.status === 'timeout' || result.status === 'failed') {
    const fallbackPorts = [22, 80, 443];
    for (const fbPort of fallbackPorts) {
      if (fbPort === port) continue; // skip if already tested
      const fbResult = await testTcp(host, fbPort, 1000);
      if (fbResult.status === 'open' || fbResult.status === 'reachable') {
        result = fbResult;
        break;
      }
    }
  }
  
  if (result.delay !== undefined) {
    return NextResponse.json({ ping: result.delay });
  } else {
    return NextResponse.json({ error: result.error || 'Server is unreachable' }, { status: 504 });
  }
}
