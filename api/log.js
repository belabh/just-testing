import UAParser from 'ua-parser-js';

// 🎯 Enhanced IP Geolocation Service
async function getLocationData(ip) {
  try {
    // Clean IP (remove ::ffff: prefix for IPv4-mapped IPv6)
    const cleanIp = ip?.replace(/^::ffff:/, '') || '';
    
    // Skip private/local IPs
    if (!cleanIp || cleanIp === '127.0.0.1' || cleanIp.startsWith('192.168.') || 
        cleanIp.startsWith('10.') || cleanIp.startsWith('172.')) {
      return { country: '🏠 Local/Private', city: 'Local Network', isp: 'Private Network' };
    }

    const response = await fetch(`http://ip-api.com/json/${cleanIp}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query`, {
      timeout: 5000
    });
    
    if (!response.ok) throw new Error('Geolocation API failed');
    
    const data = await response.json();
    
    if (data.status === 'fail') {
      throw new Error(data.message || 'Geolocation failed');
    }
    
    return {
      continent: data.continent || 'Unknown',
      country: `${data.country || 'Unknown'} ${getCountryFlag(data.countryCode)}`,
      region: data.regionName || 'Unknown',
      city: data.city || 'Unknown',
      zip: data.zip || 'Unknown',
      coordinates: data.lat && data.lon ? `${data.lat}, ${data.lon}` : 'Unknown',
      timezone: data.timezone || 'Unknown',
      currency: data.currency || 'Unknown',
      isp: data.isp || 'Unknown',
      org: data.org || 'Unknown',
      asn: data.as || 'Unknown',
      isMobile: data.mobile || false,
      isProxy: data.proxy || false,
      isHosting: data.hosting || false,
      query: data.query || cleanIp
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

// 🏳️ Country flag helper
function getCountryFlag(countryCode) {
  if (!countryCode) return '🌍';
  const flags = {
    'US': '🇺🇸', 'GB': '🇬🇧', 'CA': '🇨🇦', 'AU': '🇦🇺', 'DE': '🇩🇪',
    'FR': '🇫🇷', 'IT': '🇮🇹', 'ES': '🇪🇸', 'NL': '🇳🇱', 'BR': '🇧🇷',
    'IN': '🇮🇳', 'CN': '🇨🇳', 'JP': '🇯🇵', 'KR': '🇰🇷', 'RU': '🇷🇺',
    'EG': '🇪🇬', 'SA': '🇸🇦', 'AE': '🇦🇪', 'TR': '🇹🇷', 'IL': '🇮🇱'
  };
  return flags[countryCode] || '🌍';
}

// 🎨 Enhanced Discord Embed
function createDiscordEmbed(visitorData, geoData, deviceInfo) {
  const embed = {
    title: "🔥 New Visitor Alert!",
    color: visitorData.isUnique ? 0x00ff00 : 0xffa500, // Green for new, Orange for returning
    timestamp: new Date().toISOString(),
    thumbnail: {
      url: "https://cdn.discordapp.com/emojis/1234567890123456789.gif" // Add your custom emoji URL
    },
    fields: [
      {
        name: "🌐 Location Details",
        value: `**Country:** ${geoData.country}\n**Region:** ${geoData.region}\n**City:** ${geoData.city}\n**Coordinates:** ${geoData.coordinates}\n**Timezone:** ${geoData.timezone}`,
        inline: true
      },
      {
        name: "📱 Device Information",
        value: `**OS:** ${deviceInfo.os}\n**Browser:** ${deviceInfo.browser}\n**Device:** ${deviceInfo.device}\n**Mobile:** ${geoData.isMobile ? '✅' : '❌'}`,
        inline: true
      },
      {
        name: "🌍 Network Information",
        value: `**IP:** \`${visitorData.ip}\`\n**ISP:** ${geoData.isp}\n**Org:** ${geoData.org}\n**ASN:** ${geoData.asn}`,
        inline: false
      },
      {
        name: "🔍 Security Flags",
        value: `**Proxy:** ${geoData.isProxy ? '⚠️ Yes' : '✅ No'}\n**Hosting:** ${geoData.isHosting ? '⚠️ Yes' : '✅ No'}\n**Mobile:** ${geoData.isMobile ? '📱 Yes' : '🖥️ No'}`,
        inline: true
      },
      {
        name: "📊 Visit Information",
        value: `**Referrer:** ${visitorData.referrer}\n**Time:** ${visitorData.time}\n**Status:** ${visitorData.isUnique ? '🆕 New Visitor' : '🔄 Returning'}`,
        inline: true
      }
    ],
    footer: {
      text: `Visitor Tracker • ${visitorData.requestId}`,
      icon_url: "https://cdn.discordapp.com/emojis/1234567890123456789.png"
    }
  };

  if (geoData.coordinates !== 'Unknown') {
    embed.fields.push({
      name: "🗺️ Map Location",
      value: `[View on Google Maps](https://www.google.com/maps?q=${geoData.coordinates})`,
      inline: false
    });
  }

  return { embeds: [embed] };
}

// 📱 Enhanced Telegram Message
function createTelegramMessage(visitorData, geoData, deviceInfo) {
  const securityFlags = [];
  if (geoData.isProxy) securityFlags.push('🛡️ Proxy');
  if (geoData.isHosting) securityFlags.push('🏢 Hosting');
  if (geoData.isMobile) securityFlags.push('📱 Mobile');
  
  const statusEmoji = visitorData.isUnique ? '🆕' : '🔄';
  const securityInfo = securityFlags.length > 0 ? securityFlags.join(' • ') : '✅ Clean';

  return `
${statusEmoji} *VISITOR DETECTED*

🌍 *Location Information*
├ Country: ${geoData.country}
├ Region: ${geoData.region}
├ City: ${geoData.city}
├ Coordinates: \`${geoData.coordinates}\`
└ Timezone: ${geoData.timezone}

📱 *Device Details*
├ Operating System: ${deviceInfo.os}
├ Browser Engine: ${deviceInfo.browser}
├ Device Type: ${deviceInfo.device}
└ Screen Resolution: ${deviceInfo.screenInfo}

🌐 *Network Information*
├ IP Address: \`${visitorData.ip}\`
├ Internet Provider: ${geoData.isp}
├ Organization: ${geoData.org}
└ ASN: ${geoData.asn}

🔐 *Security Analysis*
├ Security Flags: ${securityInfo}
├ Connection Type: ${geoData.isMobile ? 'Mobile Data' : 'Fixed Broadband'}
└ Risk Level: ${geoData.isProxy || geoData.isHosting ? '⚠️ Medium' : '✅ Low'}

📊 *Visit Details*
├ Referrer: ${visitorData.referrer}
├ Timestamp: ${visitorData.time}
├ Request ID: \`${visitorData.requestId}\`
└ Status: ${visitorData.isUnique ? 'New Visitor' : 'Returning Visitor'}

${geoData.coordinates !== 'Unknown' ? `🗺️ [View Location](https://www.google.com/maps?q=${geoData.coordinates})` : ''}
  `.trim();
}

// 🔧 Enhanced Device Information Parser
function parseDeviceInfo(userAgent) {
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
    screenInfo: 'Unknown' // This would need to be passed from client-side
  };
}

// 🎲 Generate unique request ID
function generateRequestId() {
  return `VT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// 🚀 Rate limiting helper (simple in-memory store)
const visitLog = new Map();

function isUniqueVisitor(ip, timeWindow = 1800000) { // 30 minutes
  const now = Date.now();
  const lastVisit = visitLog.get(ip);
  
  if (!lastVisit || (now - lastVisit) > timeWindow) {
    visitLog.set(ip, now);
    return true;
  }
  
  return false;
}

// 🛡️ Security headers helper
function setSecurityHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
}

// 🎯 Main Handler Function
export default async function handler(req, res) {
  try {
    // 🛡️ Set security headers
    setSecurityHeaders(res);
    
    // ✅ Handle preflight request
    if (req.method === "OPTIONS") {
      return res.status(200).end();
    }
    
    // 🔍 Extract visitor information
    const ip = req.headers["x-forwarded-for"]?.split(',')[0]?.trim() || 
               req.headers["x-real-ip"] || 
               req.socket.remoteAddress || 
               'Unknown';
    
    const userAgent = req.headers["user-agent"] || 'Unknown User Agent';
    const referrer = req.headers["referer"] || req.headers["referrer"] || "Direct Visit";
    const acceptLanguage = req.headers["accept-language"] || 'Unknown';
    const acceptEncoding = req.headers["accept-encoding"] || 'Unknown';
    const requestId = generateRequestId();
    const timestamp = new Date();
    const time = timestamp.toLocaleString("en-EG", { 
      timeZone: "Africa/Cairo",
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
    
    // 🎯 Check if unique visitor
    const isUnique = isUniqueVisitor(ip);
    
    // 📱 Parse device information
    const deviceInfo = parseDeviceInfo(userAgent);
    
    // 🌍 Get geolocation data
    const geoData = await getLocationData(ip);
    
    // 📊 Compile visitor data
    const visitorData = {
      ip,
      userAgent,
      referrer,
      acceptLanguage,
      acceptEncoding,
      time,
      timestamp: timestamp.toISOString(),
      requestId,
      isUnique
    };
    
    // 📱 Send to Telegram (if enabled)
    if (process.env.TELEGRAM_ENABLED === "true") {
      const telegramToken = process.env.TELEGRAM_TOKEN;
      const telegramChatId = process.env.TELEGRAM_CHAT_ID;
      
      if (telegramToken && telegramChatId) {
        const message = createTelegramMessage(visitorData, geoData, deviceInfo);
        
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
        const embedData = createDiscordEmbed(visitorData, geoData, deviceInfo);
        
        await fetch(discordWebhook, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: "Visitor Tracker",
            avatar_url: "https://cdn.discordapp.com/emojis/1234567890123456789.png",
            ...embedData
          }),
        }).catch(err => console.error('Discord error:', err));
      }
    }
    
    // ✅ Success response with detailed information
    res.status(200).json({ 
      success: true,
      message: "Visitor tracked successfully",
      data: {
        requestId,
        timestamp: visitorData.timestamp,
        isUnique,
        location: {
          country: geoData.country,
          city: geoData.city
        },
        device: deviceInfo.device,
        browser: deviceInfo.browser
      }
    });
    
  } catch (error) {
    console.error('Handler error:', error);
    
    // 🚨 Error response
    res.status(500).json({
      success: false,
      error: "Internal server error",
      timestamp: new Date().toISOString()
    });
  }
}

// 📋 Environment Variables Required:
/*
TELEGRAM_ENABLED=true/false
TELEGRAM_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
DISCORD_ENABLED=true/false
DISCORD_WEBHOOK=your_webhook_url
*/
