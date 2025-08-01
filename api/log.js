import UAParser from 'ua-parser-js';
import crypto from 'crypto';

// 🎯 Enhanced IP Geolocation Service with Multiple Providers
async function getLocationData(ip) {
  try {
    // Clean IP (remove ::ffff: prefix for IPv4-mapped IPv6)
    const cleanIp = ip?.replace(/^::ffff:/, '') || '';
    
    // Skip private/local IPs
    if (!cleanIp || cleanIp === '127.0.0.1' || cleanIp.startsWith('192.168.') || 
        cleanIp.startsWith('10.') || cleanIp.startsWith('172.')) {
      return { 
        country: '🏠 Local/Private', 
        city: 'Local Network', 
        isp: 'Private Network',
        isLocal: true
      };
    }

    // Primary API (ip-api.com) - Free, comprehensive
    try {
      const response = await fetch(`http://ip-api.com/json/${cleanIp}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query`, {
        timeout: 5000
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          return await enrichLocationData(data, cleanIp);
        }
      }
    } catch (error) {
      console.warn('Primary geolocation failed, trying backup...');
    }

    // Backup API (ipapi.co) - Free tier available
    try {
      const backupResponse = await fetch(`https://ipapi.co/${cleanIp}/json/`, {
        timeout: 5000
      });
      
      if (backupResponse.ok) {
        const backupData = await backupResponse.json();
        return await enrichLocationData(backupData, cleanIp, true);
      }
    } catch (backupError) {
      console.warn('Backup geolocation failed');
    }
    
    return { 
      country: '🌍 Unknown Location', 
      city: 'Unknown', 
      isp: 'Unknown',
      error: 'All geolocation services failed'
    };
  } catch (error) {
    console.error('Geolocation error:', error);
    return { 
      country: '🌍 Unknown Location', 
      city: 'Unknown', 
      isp: 'Unknown',
      error: error.message 
    };
  }
}

// 🔍 Enrich location data with additional information
async function enrichLocationData(data, ip, isBackup = false) {
  const enriched = {
    continent: data.continent || data.continent_code || 'Unknown',
    country: `${data.country || 'Unknown'} ${getCountryFlag(data.country_code || data.countryCode)}`,
    countryCode: data.country_code || data.countryCode || 'Unknown',
    region: data.region || data.regionName || data.region_name || 'Unknown',
    regionCode: data.region_code || data.regionCode || 'Unknown',
    city: data.city || 'Unknown',
    district: data.district || 'Unknown',
    zip: data.postal || data.zip || 'Unknown',
    coordinates: (data.latitude || data.lat) && (data.longitude || data.lon) ? 
      `${data.latitude || data.lat}, ${data.longitude || data.lon}` : 'Unknown',
    timezone: data.timezone || 'Unknown',
    utcOffset: data.utc_offset || data.offset || 'Unknown',
    currency: data.currency || 'Unknown',
    languages: data.languages || 'Unknown',
    callingCode: data.calling_code || 'Unknown',
    isp: data.isp || 'Unknown',
    org: data.org || data.organization || 'Unknown',
    asn: data.as || data.asn || 'Unknown',
    asnOrg: data.asname || 'Unknown',
    isMobile: data.mobile || false,
    isProxy: data.proxy || false,
    isHosting: data.hosting || false,
    connection: data.connection_type || 'Unknown',
    query: data.query || ip,
    isBackup
  };

  // Add additional threat intelligence
  enriched.threatInfo = await checkThreatIntelligence(ip);
  
  return enriched;
}

// 🛡️ Basic threat intelligence check
async function checkThreatIntelligence(ip) {
  try {
    // Check against AbuseIPDB-style free services
    const threatChecks = {
      isVPN: false,
      isTor: false,
      isMalicious: false,
      reputation: 'Unknown',
      threatLevel: 'Low'
    };

    // You can add actual threat intelligence API calls here
    // For now, we'll do basic checks based on patterns
    
    // Basic VPN/Proxy detection patterns
    if (ip.includes('proxy') || ip.includes('vpn')) {
      threatChecks.isVPN = true;
      threatChecks.threatLevel = 'Medium';
    }

    return threatChecks;
  } catch (error) {
    return {
      isVPN: false,
      isTor: false,
      isMalicious: false,
      reputation: 'Unknown',
      threatLevel: 'Unknown'
    };
  }
}

// 🏳️ Enhanced country flag helper with more countries
function getCountryFlag(countryCode) {
  if (!countryCode) return '🌍';
  const flags = {
    'US': '🇺🇸', 'GB': '🇬🇧', 'CA': '🇨🇦', 'AU': '🇦🇺', 'DE': '🇩🇪',
    'FR': '🇫🇷', 'IT': '🇮🇹', 'ES': '🇪🇸', 'NL': '🇳🇱', 'BR': '🇧🇷',
    'IN': '🇮🇳', 'CN': '🇨🇳', 'JP': '🇯🇵', 'KR': '🇰🇷', 'RU': '🇷🇺',
    'EG': '🇪🇬', 'SA': '🇸🇦', 'AE': '🇦🇪', 'TR': '🇹🇷', 'IL': '🇮🇱',
    'MX': '🇲🇽', 'AR': '🇦🇷', 'CL': '🇨🇱', 'CO': '🇨🇴', 'PE': '🇵🇪',
    'SE': '🇸🇪', 'NO': '🇳🇴', 'DK': '🇩🇰', 'FI': '🇫🇮', 'PL': '🇵🇱',
    'CZ': '🇨🇿', 'AT': '🇦🇹', 'CH': '🇨🇭', 'BE': '🇧🇪', 'PT': '🇵🇹',
    'GR': '🇬🇷', 'HU': '🇭🇺', 'RO': '🇷🇴', 'BG': '🇧🇬', 'HR': '🇭🇷',
    'ZA': '🇿🇦', 'NG': '🇳🇬', 'KE': '🇰🇪', 'MA': '🇲🇦', 'TN': '🇹🇳',
    'TH': '🇹🇭', 'VN': '🇻🇳', 'SG': '🇸🇬', 'MY': '🇲🇾', 'ID': '🇮🇩',
    'PH': '🇵🇭', 'PK': '🇵🇰', 'BD': '🇧🇩', 'LK': '🇱🇰', 'NP': '🇳🇵',
    'UA': '🇺🇦', 'BY': '🇧🇾', 'KZ': '🇰🇿', 'UZ': '🇺🇿', 'MD': '🇲🇩',
    'IR': '🇮🇷', 'IQ': '🇮🇶', 'SY': '🇸🇾', 'JO': '🇯🇴', 'LB': '🇱🇧',
    'QA': '🇶🇦', 'KW': '🇰🇼', 'BH': '🇧🇭', 'OM': '🇴🇲', 'YE': '🇾🇪'
  };
  return flags[countryCode.toUpperCase()] || '🌍';
}

// 🎨 Enhanced Discord Embed with more information
function createDiscordEmbed(visitorData, geoData, deviceInfo, sessionInfo) {
  const statusColor = visitorData.isUnique ? 0x00ff00 : 
                     geoData.threatInfo?.threatLevel === 'High' ? 0xff0000 :
                     geoData.threatInfo?.threatLevel === 'Medium' ? 0xffa500 : 0x00ff00;

  const embed = {
    title: "🔥 New Visitor Detection",
    color: statusColor,
    timestamp: new Date().toISOString(),
    thumbnail: {
      url: "https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/72x72/1f310.png"
    },
    fields: [
      {
        name: "🌐 Geographic Information",
        value: `**Country:** ${geoData.country} (${geoData.countryCode})\n**Region:** ${geoData.region} (${geoData.regionCode})\n**City:** ${geoData.city}\n**District:** ${geoData.district}\n**ZIP:** ${geoData.zip}\n**Coordinates:** ${geoData.coordinates}\n**Timezone:** ${geoData.timezone} (UTC${geoData.utcOffset})`,
        inline: true
      },
      {
        name: "📱 Device & Browser",
        value: `**OS:** ${deviceInfo.os} (${deviceInfo.cpu})\n**Browser:** ${deviceInfo.browser}\n**Engine:** ${deviceInfo.engine}\n**Device:** ${deviceInfo.device}\n**Mobile:** ${geoData.isMobile ? '📱 Yes' : '🖥️ No'}\n**Languages:** ${visitorData.languages}`,
        inline: true
      },
      {
        name: "🌍 Network Details",
        value: `**IP:** \`${visitorData.ip}\`\n**ISP:** ${geoData.isp}\n**Organization:** ${geoData.org}\n**ASN:** ${geoData.asn}\n**Connection:** ${geoData.connection}\n**Hash:** \`${sessionInfo.visitorHash}\``,
        inline: false
      },
      {
        name: "🔍 Security Analysis",
        value: `**Proxy:** ${geoData.isProxy ? '⚠️ Detected' : '✅ None'}\n**VPN:** ${geoData.threatInfo?.isVPN ? '⚠️ Detected' : '✅ None'}\n**Hosting:** ${geoData.isHosting ? '⚠️ Yes' : '✅ No'}\n**Threat Level:** ${getThreatEmoji(geoData.threatInfo?.threatLevel)} ${geoData.threatInfo?.threatLevel}\n**Reputation:** ${geoData.threatInfo?.reputation}`,
        inline: true
      },
      {
        name: "📊 Session Information",
        value: `**Referrer:** ${visitorData.referrer}\n**Method:** ${visitorData.method}\n**Protocol:** ${visitorData.protocol}\n**Time:** ${visitorData.time}\n**Status:** ${visitorData.isUnique ? '🆕 New' : '🔄 Returning'}\n**Session:** ${sessionInfo.sessionType}`,
        inline: true
      },
      {
        name: "🔧 Technical Details",
        value: `**User Agent:** \`${visitorData.userAgent.substring(0, 100)}${visitorData.userAgent.length > 100 ? '...' : ''}\`\n**Accept:** ${visitorData.acceptTypes}\n**Encoding:** ${visitorData.acceptEncoding}\n**Request ID:** \`${visitorData.requestId}\``,
        inline: false
      }
    ],
    footer: {
      text: `Advanced Visitor Tracker v2.0 • ${new Date().toLocaleString()}`,
      icon_url: "https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/72x72/1f4e1.png"
    }
  };

  // Add map link if coordinates are available
  if (geoData.coordinates !== 'Unknown') {
    embed.fields.push({
      name: "🗺️ Location Services",
      value: `[Google Maps](https://www.google.com/maps?q=${geoData.coordinates}) • [OpenStreetMap](https://www.openstreetmap.org/?mlat=${geoData.coordinates.split(',')[0]}&mlon=${geoData.coordinates.split(',')[1]}&zoom=12)`,
      inline: false
    });
  }

  return { embeds: [embed] };
}

// 🚨 Threat level emoji helper
function getThreatEmoji(threatLevel) {
  const emojis = {
    'Low': '🟢',
    'Medium': '🟡',
    'High': '🔴',
    'Critical': '🚨',
    'Unknown': '⚪'
  };
  return emojis[threatLevel] || '⚪';
}

// 📱 Enhanced Telegram Message with comprehensive information
function createTelegramMessage(visitorData, geoData, deviceInfo, sessionInfo) {
  const securityFlags = [];
  if (geoData.isProxy) securityFlags.push('🛡️ Proxy');
  if (geoData.threatInfo?.isVPN) securityFlags.push('🔒 VPN');
  if (geoData.isHosting) securityFlags.push('🏢 Hosting');
  if (geoData.isMobile) securityFlags.push('📱 Mobile');
  
  const statusEmoji = visitorData.isUnique ? '🆕' : '🔄';
  const threatEmoji = getThreatEmoji(geoData.threatInfo?.threatLevel);
  const securityInfo = securityFlags.length > 0 ? securityFlags.join(' • ') : '✅ Clean';

  return `
${statusEmoji} *ADVANCED VISITOR DETECTION* ${threatEmoji}

🌍 *Geographic Intelligence*
├ Country: ${geoData.country}
├ Region: ${geoData.region} (${geoData.regionCode})
├ City: ${geoData.city}
├ District: ${geoData.district}
├ Postal Code: ${geoData.zip}
├ Coordinates: \`${geoData.coordinates}\`
├ Timezone: ${geoData.timezone}
├ UTC Offset: ${geoData.utcOffset}
├ Currency: ${geoData.currency}
└ Languages: ${geoData.languages}

📱 *Device Intelligence*
├ Operating System: ${deviceInfo.os}
├ Browser Engine: ${deviceInfo.browser}
├ Rendering Engine: ${deviceInfo.engine}
├ CPU Architecture: ${deviceInfo.cpu}
├ Device Type: ${deviceInfo.device}
├ Accept Languages: ${visitorData.languages}
└ Mobile Device: ${geoData.isMobile ? '✅ Yes' : '❌ No'}

🌐 *Network Intelligence*
├ IP Address: \`${visitorData.ip}\`
├ Internet Provider: ${geoData.isp}
├ Organization: ${geoData.org}
├ ASN: ${geoData.asn}
├ ASN Organization: ${geoData.asnOrg}
├ Connection Type: ${geoData.connection}
└ Visitor Hash: \`${sessionInfo.visitorHash}\`

🔐 *Security Analysis*
├ Security Flags: ${securityInfo}
├ Threat Level: ${threatEmoji} ${geoData.threatInfo?.threatLevel}
├ Reputation Score: ${geoData.threatInfo?.reputation}
├ VPN Detection: ${geoData.threatInfo?.isVPN ? '⚠️ Detected' : '✅ Clean'}
├ Proxy Detection: ${geoData.isProxy ? '⚠️ Detected' : '✅ Clean'}
├ Hosting Service: ${geoData.isHosting ? '⚠️ Yes' : '✅ No'}
└ Risk Assessment: ${assessRiskLevel(geoData)}

📊 *Session Intelligence*
├ HTTP Method: ${visitorData.method}
├ Protocol: ${visitorData.protocol}
├ Referrer Source: ${visitorData.referrer}
├ Accept Types: ${visitorData.acceptTypes}
├ Encoding Support: ${visitorData.acceptEncoding}
├ Session Type: ${sessionInfo.sessionType}
├ Visit Status: ${visitorData.isUnique ? '🆕 First Visit' : '🔄 Returning Visitor'}
├ Local Time: ${visitorData.time}
├ Request ID: \`${visitorData.requestId}\`
└ Fingerprint: \`${sessionInfo.fingerprint}\`

🔧 *Technical Details*
├ User Agent: \`${visitorData.userAgent.substring(0, 80)}${visitorData.userAgent.length > 80 ? '...' : ''}\`
├ Content Types: ${visitorData.acceptTypes}
├ Cache Control: ${visitorData.cacheControl || 'Not specified'}
└ Connection: ${visitorData.connection || 'Standard'}

${geoData.coordinates !== 'Unknown' ? `🗺️ *Location Services*
├ [Google Maps](https://www.google.com/maps?q=${geoData.coordinates})
├ [OpenStreetMap](https://www.openstreetmap.org/?mlat=${geoData.coordinates.split(',')[0]}&mlon=${geoData.coordinates.split(',')[1]}&zoom=12)
└ [Weather Info](https://wttr.in/${geoData.city})` : ''}

⏰ *Timestamp: ${new Date().toISOString()}*
  `.trim();
}

// 🎲 Risk assessment helper
function assessRiskLevel(geoData) {
  let risk = 'Low';
  if (geoData.isProxy || geoData.threatInfo?.isVPN) risk = 'Medium';
  if (geoData.isHosting && geoData.isProxy) risk = 'High';
  if (geoData.threatInfo?.isMalicious) risk = 'Critical';
  return `${getThreatEmoji(risk)} ${risk}`;
}

// 🔧 Enhanced Device Information Parser
function parseDeviceInfo(userAgent, acceptLanguage, headers) {
  const parser = new UAParser(userAgent);
  const result = parser.getResult();
  
  return {
    browser: `${result.browser.name || 'Unknown'} ${result.browser.version || ''}`.trim(),
    os: `${result.os.name || 'Unknown'} ${result.os.version || ''}`.trim(),
    device: result.device.type ? 
      `${result.device.vendor || ''} ${result.device.model || ''} (${result.device.type})`.trim() : 
      'Desktop/Laptop',
    engine: `${result.engine.name || 'Unknown'} ${result.engine.version || ''}`.trim(),
    cpu: result.cpu.architecture || 'Unknown',
    screenInfo: 'Unknown', // Would need client-side JavaScript
    languages: acceptLanguage || 'Unknown',
    platform: result.os.name || 'Unknown',
    deviceMemory: headers['device-memory'] || 'Unknown',
    hardwareConcurrency: headers['sec-ch-ua-mobile'] || 'Unknown'
  };
}

// 🔒 Generate visitor fingerprint
function generateVisitorFingerprint(ip, userAgent, acceptLanguage, acceptEncoding) {
  const data = `${ip}:${userAgent}:${acceptLanguage}:${acceptEncoding}`;
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

// 🎲 Generate unique request ID with more entropy
function generateRequestId() {
  const timestamp = Date.now();
  const randomBytes = crypto.randomBytes(8).toString('hex');
  return `VT-${timestamp}-${randomBytes}`;
}

// 📊 Enhanced session analysis
function analyzeSession(req, visitorData, isUnique) {
  const fingerprint = generateVisitorFingerprint(
    visitorData.ip, 
    visitorData.userAgent, 
    req.headers["accept-language"], 
    req.headers["accept-encoding"]
  );
  
  const visitorHash = crypto.createHash('md5')
    .update(`${visitorData.ip}:${visitorData.userAgent}`)
    .digest('hex')
    .substring(0, 12);

  return {
    fingerprint,
    visitorHash,
    sessionType: isUnique ? 'New Session' : 'Returning Session',
    sessionId: `${visitorHash}-${Date.now()}`,
    trustLevel: calculateTrustLevel(req.headers)
  };
}

// 📈 Calculate trust level based on headers
function calculateTrustLevel(headers) {
  let score = 50; // Base score
  
  if (headers['sec-fetch-site']) score += 10;
  if (headers['sec-fetch-mode']) score += 10;
  if (headers['sec-fetch-dest']) score += 10;
  if (headers['accept-language']?.includes(',')) score += 5;
  if (headers['accept-encoding']?.includes('gzip')) score += 5;
  if (headers['cache-control']) score += 5;
  if (headers['dnt'] === '1') score += 10; // Do Not Track
  
  if (score >= 80) return 'High';
  if (score >= 60) return 'Medium';
  return 'Low';
}

// 🚀 Enhanced rate limiting with visitor tracking
const visitLog = new Map();
const visitorStats = new Map();

function trackVisitor(ip, userAgent, timeWindow = 1800000) { // 30 minutes
  const now = Date.now();
  const visitorKey = crypto.createHash('md5').update(`${ip}:${userAgent}`).digest('hex');
  
  // Update visit statistics
  if (!visitorStats.has(visitorKey)) {
    visitorStats.set(visitorKey, {
      firstVisit: now,
      visitCount: 0,
      lastVisit: 0
    });
  }
  
  const stats = visitorStats.get(visitorKey);
  const isUnique = !visitLog.has(visitorKey) || (now - visitLog.get(visitorKey)) > timeWindow;
  
  if (isUnique) {
    visitLog.set(visitorKey, now);
    stats.visitCount++;
    stats.lastVisit = now;
  }
  
  return {
    isUnique,
    visitCount: stats.visitCount,
    firstVisit: new Date(stats.firstVisit).toISOString(),
    lastVisit: new Date(stats.lastVisit).toISOString()
  };
}

// 🛡️ Enhanced security headers
function setSecurityHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, User-Agent");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
}

// 🎯 Main Enhanced Handler Function
export default async function handler(req, res) {
  try {
    // 🛡️ Set enhanced security headers
    setSecurityHeaders(res);
    
    // ✅ Handle preflight request
    if (req.method === "OPTIONS") {
      return res.status(204).end();
    }
    
    // 🔍 Extract comprehensive visitor information
    const ip = req.headers["x-forwarded-for"]?.split(',')[0]?.trim() || 
               req.headers["x-real-ip"] || 
               req.headers["cf-connecting-ip"] || // Cloudflare
               req.headers["x-client-ip"] || 
               req.socket.remoteAddress || 
               'Unknown';
    
    const userAgent = req.headers["user-agent"] || 'Unknown User Agent';
    const referrer = req.headers["referer"] || req.headers["referrer"] || "Direct Visit";
    const acceptLanguage = req.headers["accept-language"] || 'Unknown';
    const acceptEncoding = req.headers["accept-encoding"] || 'Unknown';
    const acceptTypes = req.headers["accept"] || 'Unknown';
    const cacheControl = req.headers["cache-control"] || null;
    const connection = req.headers["connection"] || null;
    const requestId = generateRequestId();
    const timestamp = new Date();
    const time = timestamp.toLocaleString("en-EG", { 
      timeZone: "Africa/Cairo",
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short'
    });
    
    // 🎯 Enhanced visitor tracking
    const visitorTracking = trackVisitor(ip, userAgent);
    
    // 📱 Parse enhanced device information
    const deviceInfo = parseDeviceInfo(userAgent, acceptLanguage, req.headers);
    
    // 🌍 Get comprehensive geolocation data
    const geoData = await getLocationData(ip);
    
    // 📊 Compile comprehensive visitor data
    const visitorData = {
      ip,
      userAgent,
      referrer,
      acceptLanguage,
      acceptEncoding,
      acceptTypes,
      cacheControl,
      connection,
      method: req.method,
      protocol: req.headers["x-forwarded-proto"] || 'http',
      time,
      timestamp: timestamp.toISOString(),
      requestId,
      isUnique: visitorTracking.isUnique,
      visitCount: visitorTracking.visitCount,
      languages: acceptLanguage?.split(',').map(l => l.trim().split(';')[0]).join(', ') || 'Unknown'
    };
    
    // 🔒 Generate session information
    const sessionInfo = analyzeSession(req, visitorData, visitorTracking.isUnique);
    
    // 📱 Send to Telegram (if enabled)
    if (process.env.TELEGRAM_ENABLED === "true") {
      const telegramToken = process.env.TELEGRAM_TOKEN;
      const telegramChatId = process.env.TELEGRAM_CHAT_ID;
      
      if (telegramToken && telegramChatId) {
        const message = createTelegramMessage(visitorData, geoData, deviceInfo, sessionInfo);
        
        await fetch(`https://api.telegram.org/bot${telegramToken}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: telegramChatId,
            text: message,
            parse_mode: "Markdown",
            disable_web_page_preview: false
          }),
        }).catch(err => console.error('Telegram error:', err));
      }
    }
    
    // 🎮 Send to Discord (if enabled)
    if (process.env.DISCORD_ENABLED === "true") {
      const discordWebhook = process.env.DISCORD_WEBHOOK;
      
      if (discordWebhook) {
        const embedData = createDiscordEmbed(visitorData, geoData, deviceInfo, sessionInfo);
        
        await fetch(discordWebhook, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: "Advanced Visitor Tracker",
            avatar_url: "https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/72x72/1f4e1.png",
            ...embedData
          }),
        }).catch(err => console.error('Discord error:', err));
      }
    }
    
    // 📧 Send to Email (if enabled) - New feature
    if (process.env.EMAIL_ENABLED === "true") {
      await sendEmailNotification(visitorData, geoData, deviceInfo, sessionInfo);
    }
    
    // 💾 Log to database (if enabled) - New feature
    if (process.env.DATABASE_ENABLED === "true") {
      await logToDatabase(visitorData, geoData, deviceInfo, sessionInfo);
    }
    
    // ✅ Enhanced success response
    res.status(200).json({ 
      success: true,
      message: "Visitor tracked successfully with enhanced data collection",
      data: {
        requestId,
        timestamp: visitorData.timestamp,
        tracking: {
          isUnique: visitorTracking.isUnique,
          visitCount: visitorTracking.visitCount,
          sessionType: sessionInfo.sessionType
        },
        location: {
          country: geoData.country,
          city: geoData.city,
          coordinates: geoData.coordinates
        },
        device: {
          type: deviceInfo.device,
          browser: deviceInfo.browser,
          os: deviceInfo.os
        },
        security: {
          threatLevel: geoData.threatInfo?.threatLevel,
          trustLevel: sessionInfo.trustLevel,
          fingerprint: sessionInfo.fingerprint
        }
      }
    });
    
  } catch (error) {
    console.error('Handler error:', error);
    
    // 🚨 Enhanced error response
    res.status(500).json({
      success: false,
      error: "Internal server error",
      timestamp: new Date().toISOString(),
      requestId: generateRequestId()
    });
  }
}

// 📧 Email notification function (new feature)
async function sendEmailNotification(visitorData, geoData, deviceInfo, sessionInfo) {
  try {
    if (!process.env.EMAIL_SERVICE_URL || !process.env.EMAIL_API_KEY) return;
    
    const emailContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
            .info-block { background: #f8f9fa; border-left: 4px solid #007bff; margin: 10px 0; padding: 15px; border-radius: 5px; }
            .alert { background: #fff3cd; border-left: 4px solid #ffc107; color: #856404; }
            .danger { background: #f8d7da; border-left: 4px solid #dc3545; color: #721c24; }
            .success { background: #d4edda; border-left: 4px solid #28a745; color: #155724; }
            .footer { background: #343a40; color: white; padding: 15px; text-align: center; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔥 Visitor Detection Alert</h1>
                <p>Advanced tracking system has detected a new visitor</p>
            </div>
            <div class="content">
                <div class="info-block ${geoData.threatInfo?.threatLevel === 'High' ? 'danger' : 'success'}">
                    <h3>🌍 Geographic Information</h3>
                    <p><strong>Location:</strong> ${geoData.city}, ${geoData.region}, ${geoData.country}</p>
                    <p><strong>Coordinates:</strong> ${geoData.coordinates}</p>
                    <p><strong>ISP:</strong> ${geoData.isp}</p>
                    <p><strong>Timezone:</strong> ${geoData.timezone}</p>
                </div>
                
                <div class="info-block">
                    <h3>📱 Device Information</h3>
                    <p><strong>Device:</strong> ${deviceInfo.device}</p>
                    <p><strong>Browser:</strong> ${deviceInfo.browser}</p>
                    <p><strong>Operating System:</strong> ${deviceInfo.os}</p>
                    <p><strong>Languages:</strong> ${visitorData.languages}</p>
                </div>
                
                <div class="info-block ${geoData.isProxy || geoData.threatInfo?.isVPN ? 'alert' : 'success'}">
                    <h3>🔐 Security Analysis</h3>
                    <p><strong>IP Address:</strong> ${visitorData.ip}</p>
                    <p><strong>Threat Level:</strong> ${geoData.threatInfo?.threatLevel}</p>
                    <p><strong>VPN Detected:</strong> ${geoData.threatInfo?.isVPN ? 'Yes ⚠️' : 'No ✅'}</p>
                    <p><strong>Proxy Detected:</strong> ${geoData.isProxy ? 'Yes ⚠️' : 'No ✅'}</p>
                    <p><strong>Visitor Hash:</strong> ${sessionInfo.visitorHash}</p>
                </div>
                
                <div class="info-block">
                    <h3>📊 Visit Details</h3>
                    <p><strong>First Visit:</strong> ${visitorData.isUnique ? 'Yes 🆕' : 'No 🔄'}</p>
                    <p><strong>Referrer:</strong> ${visitorData.referrer}</p>
                    <p><strong>Time:</strong> ${visitorData.time}</p>
                    <p><strong>Request ID:</strong> ${visitorData.requestId}</p>
                </div>
            </div>
            <div class="footer">
                <p>Advanced Visitor Tracker v2.0 • Generated at ${new Date().toISOString()}</p>
            </div>
        </div>
    </body>
    </html>
    `;
    
    await fetch(process.env.EMAIL_SERVICE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.EMAIL_API_KEY}`
      },
      body: JSON.stringify({
        to: process.env.EMAIL_TO,
        subject: `🔥 New Visitor: ${geoData.city}, ${geoData.country} - ${deviceInfo.device}`,
        html: emailContent
      })
    });
  } catch (error) {
    console.error('Email notification error:', error);
  }
}

// 💾 Database logging function (new feature)
async function logToDatabase(visitorData, geoData, deviceInfo, sessionInfo) {
  try {
    if (!process.env.DATABASE_URL) return;
    
    const logEntry = {
      timestamp: visitorData.timestamp,
      requestId: visitorData.requestId,
      visitor: {
        ip: visitorData.ip,
        userAgent: visitorData.userAgent,
        fingerprint: sessionInfo.fingerprint,
        hash: sessionInfo.visitorHash,
        isUnique: visitorData.isUnique,
        visitCount: visitorData.visitCount
      },
      location: {
        country: geoData.country,
        countryCode: geoData.countryCode,
        region: geoData.region,
        city: geoData.city,
        coordinates: geoData.coordinates,
        timezone: geoData.timezone,
        isp: geoData.isp
      },
      device: {
        os: deviceInfo.os,
        browser: deviceInfo.browser,
        device: deviceInfo.device,
        mobile: geoData.isMobile
      },
      security: {
        threatLevel: geoData.threatInfo?.threatLevel,
        isProxy: geoData.isProxy,
        isVPN: geoData.threatInfo?.isVPN,
        isHosting: geoData.isHosting,
        trustLevel: sessionInfo.trustLevel
      },
      session: {
        referrer: visitorData.referrer,
        method: visitorData.method,
        protocol: visitorData.protocol,
        languages: visitorData.languages
      }
    };
    
    // Example for MongoDB/PostgreSQL/MySQL - adjust based on your database
    await fetch(`${process.env.DATABASE_URL}/api/visitors`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.DATABASE_API_KEY}`
      },
      body: JSON.stringify(logEntry)
    });
    
  } catch (error) {
    console.error('Database logging error:', error);
  }
}

// 🔍 Advanced fingerprinting (client-side companion script)
function generateClientSideScript() {
  return `
<script>
(function() {
    // Collect additional client-side information
    const clientInfo = {
        screen: {
            width: screen.width,
            height: screen.height,
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth,
            orientation: screen.orientation?.type || 'unknown'
        },
        window: {
            innerWidth: window.innerWidth,
            innerHeight: window.innerHeight,
            outerWidth: window.outerWidth,
            outerHeight: window.outerHeight,
            devicePixelRatio: window.devicePixelRatio || 1
        },
        navigator: {
            platform: navigator.platform,
            language: navigator.language,
            languages: navigator.languages,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            hardwareConcurrency: navigator.hardwareConcurrency,
            maxTouchPoints: navigator.maxTouchPoints,
            onLine: navigator.onLine,
            pdfViewerEnabled: navigator.pdfViewerEnabled,
            webdriver: navigator.webdriver
        },
        timezone: {
            offset: new Date().getTimezoneOffset(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        },
        features: {
            localStorage: typeof Storage !== 'undefined',
            sessionStorage: typeof Storage !== 'undefined',
            indexedDB: typeof indexedDB !== 'undefined',
            webGL: !!window.WebGLRenderingContext,
            canvas: !!window.CanvasRenderingContext2D,
            webRTC: !!(navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia || navigator.mediaDevices?.getUserMedia),
            geolocation: !!navigator.geolocation,
            battery: !!navigator.getBattery,
            bluetooth: !!navigator.bluetooth,
            usb: !!navigator.usb
        },
        performance: {
            memory: navigator.deviceMemory,
            connection: navigator.connection ? {
                effectiveType: navigator.connection.effectiveType,
                downlink: navigator.connection.downlink,
                rtt: navigator.connection.rtt,
                saveData: navigator.connection.saveData
            } : null
        }
    };
    
    // Generate canvas fingerprint
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Fingerprint test 🔍', 2, 2);
        clientInfo.canvasFingerprint = canvas.toDataURL().substring(0, 50);
    } catch (e) {
        clientInfo.canvasFingerprint = 'unavailable';
    }
    
    // Generate WebGL fingerprint
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            clientInfo.webGL = {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER),
                version: gl.getParameter(gl.VERSION),
                shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                extensions: gl.getSupportedExtensions()
            };
        }
    } catch (e) {
        clientInfo.webGL = 'unavailable';
    }
    
    // Send additional data to your tracking endpoint
    fetch(window.location.href, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            clientInfo: clientInfo,
            timestamp: new Date().toISOString()
        })
    }).catch(() => {}); // Silent fail
})();
</script>
  `;
}

// 📊 Analytics dashboard data generator
function generateAnalyticsSummary() {
  const stats = {
    totalVisitors: visitLog.size,
    uniqueVisitors: Array.from(visitorStats.values()).length,
    returningVisitors: Array.from(visitorStats.values()).filter(v => v.visitCount > 1).length,
    topCountries: {},
    topBrowsers: {},
    topOS: {},
    threatLevels: { Low: 0, Medium: 0, High: 0, Critical: 0 },
    lastUpdated: new Date().toISOString()
  };
  
  return stats;
}

// 🎨 Generate HTML analytics dashboard
function generateAnalyticsDashboard() {
  const stats = generateAnalyticsSummary();
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Visitor Analytics Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .dashboard { max-width: 1200px; margin: 20px auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; text-align: center; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2.5rem; font-weight: bold; color: #667eea; margin-bottom: 10px; }
        .stat-label { color: #666; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
        .chart-container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .refresh-btn { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; float: right; }
        .refresh-btn:hover { background: #5a6fd8; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>🔥 Advanced Visitor Analytics</h1>
            <p>Real-time visitor tracking and analysis dashboard</p>
            <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">${stats.totalVisitors}</div>
                <div class="stat-label">Total Visits</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.uniqueVisitors}</div>
                <div class="stat-label">Unique Visitors</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.returningVisitors}</div>
                <div class="stat-label">Returning Visitors</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${Math.round((stats.returningVisitors / stats.uniqueVisitors) * 100) || 0}%</div>
                <div class="stat-label">Return Rate</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>🌍 Geographic Distribution</h3>
            <canvas id="geoChart" width="400" height="200"></canvas>
        </div>
        
        <div class="chart-container">
            <h3>🔐 Security Threat Levels</h3>
            <canvas id="threatChart" width="400" height="200"></canvas>
        </div>
        
        <div class="chart-container">
            <h3>📱 Device Types</h3>
            <canvas id="deviceChart" width="400" height="200"></canvas>
        </div>
        
        <div style="text-align: center; color: #666; margin-top: 30px;">
            <p>Last updated: ${stats.lastUpdated}</p>
            <p>Advanced Visitor Tracker v2.0</p>
        </div>
    </div>
    
    <script>
        // Initialize charts with sample data
        // In a real implementation, this would be populated with actual data
        
        // Geographic chart
        new Chart(document.getElementById('geoChart'), {
            type: 'doughnut',
            data: {
                labels: ['Unknown', 'United States', 'Germany', 'France', 'Others'],
                datasets: [{
                    data: [30, 25, 15, 12, 18],
                    backgroundColor: ['#ff6384', '#36a2eb', '#cc65fe', '#ffce56', '#4bc0c0']
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
        
        // Threat level chart
        new Chart(document.getElementById('threatChart'), {
            type: 'bar',
            data: {
                labels: ['Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    label: 'Visitors',
                    data: [85, 12, 2, 1],
                    backgroundColor: ['#28a745', '#ffc107', '#fd7e14', '#dc3545']
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
        
        // Device chart
        new Chart(document.getElementById('deviceChart'), {
            type: 'pie',
            data: {
                labels: ['Desktop', 'Mobile', 'Tablet'],
                datasets: [{
                    data: [60, 35, 5],
                    backgroundColor: ['#667eea', '#764ba2', '#f093fb']
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    </script>
</body>
</html>
  `;
}

// 📋 Environment Variables Required:
/*
TELEGRAM_ENABLED=true/false
TELEGRAM_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

DISCORD_ENABLED=true/false
DISCORD_WEBHOOK=your_webhook_url

EMAIL_ENABLED=true/false
EMAIL_SERVICE_URL=your_email_service_endpoint
EMAIL_API_KEY=your_email_api_key
EMAIL_TO=recipient@email.com

DATABASE_ENABLED=true/false
DATABASE_URL=your_database_endpoint
DATABASE_API_KEY=your_database_api_key

// Optional threat intelligence APIs
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_virustotal_key
IPQUALITYSCORE_API_KEY=your_ipqs_key
*/
