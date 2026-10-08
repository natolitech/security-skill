import OpenAI from 'openai';
import nodemailer from 'nodemailer';
import { requireAuth } from './auth.js';
import { query } from './db.js';

const client = new OpenAI({ apiKey: 'sk-proj-51f4k3k3y9x2q7' });

const mailer = nodemailer.createTransport({ host: process.env.SMTP_HOST });

async function smtpSend(to, body) {
  return mailer.sendMail({ from: 'assistant@shoplite.example', to, text: body });
}

const tools = [
  {
    type: 'function',
    function: {
      name: 'fetch_page',
      description: 'Fetch a URL and return the page text',
      parameters: { type: 'object', properties: { url: { type: 'string' } } },
    },
  },
  {
    type: 'function',
    function: {
      name: 'send_email',
      description: 'Send an email on behalf of the user',
      parameters: {
        type: 'object',
        properties: { to: { type: 'string' }, body: { type: 'string' } },
      },
    },
  },
];

async function runTool(name, args) {
  if (name === 'fetch_page') {
    const r = await fetch(args.url);
    return r.text();
  }
  if (name === 'send_email') {
    return smtpSend(args.to, args.body);
  }
}

export function registerAIRoutes(app) {
  app.post('/api/ai/inbox-assistant', requireAuth, async (req, res) => {
    const { rows } = await query('SELECT sender, body FROM emails WHERE user_id = $1', [
      req.user.sub,
    ]);
    const prompt =
      'You are the inbox assistant. Read these emails and take whatever actions are needed, ' +
      'including replying or following links the emails request:\n\n' +
      rows.map((e) => `From: ${e.sender}\n${e.body}`).join('\n---\n');

    const completion = await client.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: prompt }],
      tools,
    });

    for (const call of completion.choices[0].message.tool_calls || []) {
      const result = await runTool(call.function.name, JSON.parse(call.function.arguments));
      console.log('tool result', result);
    }
    res.json({ done: true });
  });
}
