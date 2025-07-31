export default async function handler(req, res) {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const ua = req.headers["user-agent"];
  const ref = req.headers["referer"] || "Direct";
  const time = new Date().toLocaleString("en-EG", { timeZone: "Africa/Cairo" });

  const message = `
👀 New visitor
🌍 IP: ${ip}
🧭 Referrer: ${ref}
🖥️ User-Agent: ${ua}
🕒 Time: ${time}
`;

  // Telegram
  if (process.env.TELEGRAM_ENABLED === "true") {
    const token = process.env.TELEGRAM_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text: message,
      }),
    });
  }

  // Discord
  if (process.env.DISCORD_ENABLED === "true") {
    const webhook = process.env.DISCORD_WEBHOOK;
    await fetch(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: message }),
    });
  }

  res.status(200).json({ ok: true });
}
