import express from "express";
import nacl from "tweetnacl";
import "dotenv/config";

const app = express();
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

// ---------------------------
// Verify Discord Signature
// ---------------------------
function verifyDiscordRequest(req, res, buf) {
  const signature = req.get("X-Signature-Ed25519");
  const timestamp = req.get("X-Signature-Timestamp");
  const publicKey = process.env.DISCORD_PUBLIC_KEY;

  if (!signature || !timestamp) return false;

  return nacl.sign.detached.verify(
    Buffer.from(timestamp + buf),
    Buffer.from(signature, "hex"),
    Buffer.from(publicKey, "hex")
  );
}

// ---------------------------
// Interactions Endpoint
// ---------------------------
app.post("/api/interactions", (req, res) => {
  if (!verifyDiscordRequest(req, res, req.rawBody)) {
    return res.status(401).send("Invalid request signature");
  }

  const interaction = req.body;

  // Ping (Discord verifica il bot)
  if (interaction.type === 1) {
    return res.send({ type: 1 });
  }

  // Comando /security-key
  if (interaction.type === 2) {
    return res.send({
      type: 4,
      data: {
        content: "🔐 **Benvenuto nel sistema di sicurezza KEY Security.**\nClicca il pulsante qui sotto per verificare il tuo account.",
        components: [
          {
            type: 1,
            components: [
              {
                type: 2,
                style: 5,
                label: "Verifica Account",
                url: "https://key-security-bot.onrender.com/verify-user"
              }
            ]
          }
        ]
      }
    });
  }

  return res.send({ type: 4, data: { content: "Comando non riconosciuto." } });
});

// ---------------------------
// Verification Page
// ---------------------------
app.get("/verify-user", (req, res) => {
  res.send(`
    <html>
      <head><title>Key Security Verification</title></head>
      <body style="font-family: sans-serif; text-align: center">
        <h1>🔐 Verifica Account</h1>
        <p>Clicca per collegare il tuo profilo Discord.</p>
        <a href="https://discord.com/oauth2/authorize?client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&response_type=code&scope=identify role_connections.write">
          <button style="padding: 10px 20px;">Collega Account</button>
        </a>
      </body>
    </html>
  `);
});

// ---------------------------
// Terms & Privacy
// ---------------------------
app.get("/terms-of-service", (req, res) => {
  res.sendFile(process.cwd() + "/views/terms.html");
});

app.get("/privacy-policy", (req, res) => {
  res.sendFile(process.cwd() + "/views/privacy.html");
});

// ---------------------------
// Start Server
// ---------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port", PORT));
