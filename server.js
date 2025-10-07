// server.js
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { GoogleGenAI } from '@google/genai'; // 👈 ใช้ GoogleGenAI
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 3000;

// ----------------------------------------------------
// Middleware Configuration
// ----------------------------------------------------

// Security headers
app.use(helmet());

// CORS configuration
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
    methods: ['GET', 'POST'],
    credentials: true
};
app.use(cors(corsOptions));

// Body parser
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const chatLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 20, // limit each IP to 20 chat requests per minute
    message: { error: 'Too many chat requests, please slow down.' }
});

// ใช้ apiLimiter กับ API ทั่วไปทั้งหมด
app.use('/api/', apiLimiter); 

// ----------------------------------------------------
// Gemini Client Setup
// ----------------------------------------------------

if (!process.env.GEMINI_API_KEY) {
    console.error('❌ GEMINI_API_KEY is not set in environment variables.');
    process.exit(1);
}

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const modelName = process.env.GEMINI_MODEL || "gemini-2.5-flash";

// Session management - Store sessions per user
const userSessions = new Map();
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

// Clean up old sessions every 10 minutes
setInterval(() => {
    const now = Date.now();
    for (const [userId, session] of userSessions.entries()) {
        if (now - session.lastActivity > SESSION_TIMEOUT) {
            userSessions.delete(userId);
            console.log(`🗑️  Cleaned up session for user: ${userId}`);
        }
    }
}, 10 * 60 * 1000);

// ----------------------------------------------------
// Helper Functions
// ----------------------------------------------------

function validateMessage(message) {
    if (!message || typeof message !== 'string') {
        return { valid: false, error: 'Message must be a non-empty string.' };
    }
    
    const trimmedMessage = message.trim();
    
    if (trimmedMessage.length === 0) {
        return { valid: false, error: 'Message cannot be empty.' };
    }
    
    if (trimmedMessage.length > 5000) {
        return { valid: false, error: 'Message too long. Maximum 5000 characters.' };
    }
    
    return { valid: true, message: trimmedMessage };
}

function getUserSession(userId) {
    if (!userSessions.has(userId)) {
        const chatSession = ai.chats.create({ model: modelName });
        userSessions.set(userId, {
            session: chatSession,
            lastActivity: Date.now(),
            createdAt: Date.now()
        });
        console.log(`✨ Created new session for user: ${userId}`);
    } else {
        // Update last activity
        userSessions.get(userId).lastActivity = Date.now();
    }
    
    return userSessions.get(userId).session;
}

// ----------------------------------------------------
// API Endpoints
// ----------------------------------------------------

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        activeSessions: userSessions.size
    });
});

// ❗❗❗ Endpoint สำหรับส่งข้อความ (STREAMING LOGIC) ❗❗❗
app.post('/api/chat/send', chatLimiter, async (req, res) => {
    
    // 1. ตั้งค่า Header สำหรับ Streaming ก่อนเริ่ม Process
    res.setHeader('Content-Type', 'text/plain'); // Frontend จะอ่านเป็นข้อความดิบ
    res.setHeader('Transfer-Encoding', 'chunked');
    res.status(200); 

    try {
        const { message, userId } = req.body;
        
        // Validate userId
        if (!userId || typeof userId !== 'string') {
            if (res.headersSent) {
                return res.end(`\n\n⚠️ ERROR: Missing or invalid userId.`);
            }
            return res.status(400).json({ 
                error: 'Missing or invalid userId. Please provide a valid user identifier.' 
            });
        }
        
        // Validate message
        const validation = validateMessage(message);
        if (!validation.valid) {
            if (res.headersSent) {
                 return res.end(`\n\n⚠️ ERROR: ${validation.error}`);
            }
            return res.status(400).json({ error: validation.error });
        }
        
        console.log(`💬 User ${userId}: ${validation.message.substring(0, 50)}...`);
        
        // Get or create user session
        const chatSession = getUserSession(userId);
        
        // 2. ใช้ sendMessageStream
        const responseStream = await chatSession.sendMessageStream({ 
            message: validation.message 
        });
        
        // 3. วนลูปอ่าน Stream และใช้ res.write() ส่งกลับทีละ Chunk
        for await (const chunk of responseStream) {
            const chunkText = chunk.text;
            if (chunkText) {
                // ส่งข้อมูลออกไปทันที
                res.write(chunkText);
            }
        }
        
        console.log(`🤖 AI Response stream finished for user ${userId}`);
        
        // 4. จบการตอบกลับ
        res.end();
        
    } catch (error) {
        console.error('❌ Error in /api/chat/send:', error);
        
        // จัดการ Error: ถ้า Headers ถูกส่งไปแล้ว (res.headersSent เป็น true) ให้จบ Stream ด้วยข้อความ Error
        if (res.headersSent) {
            let errorMessage = 'Failed to get full response.';
            if (error.message?.includes('quota')) {
                 errorMessage = 'API Quota Exceeded. Please try again later.';
            } else if (error.message?.includes('API key')) {
                 errorMessage = 'Authentication error. Invalid API configuration.';
            }
            res.end(`\n\n⚠️ ERROR: ${errorMessage}`);
        } else {
             // ถ้า Headers ยังไม่ถูกส่ง ให้ส่ง Error แบบ JSON ปกติ
            const details = process.env.NODE_ENV === 'development' ? error.message : 'Internal server error';
            
            // Handle specific error types before sending generic response
            if (error.message?.includes('quota')) {
                 return res.status(429).json({ error: 'API quota exceeded. Please try again later.' });
            }
            if (error.message?.includes('API key')) {
                return res.status(401).json({ error: 'Authentication error. Invalid API configuration.' });
            }

            res.status(500).json({ 
                error: 'Failed to get response from AI.',
                details: details
            });
        }
    }
});

// Clear user session endpoint (โค้ดเดิม)
app.post('/api/chat/clear', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'Missing userId.' });
        }
        
        if (userSessions.has(userId)) {
            userSessions.delete(userId);
            console.log(`🗑️  Cleared session for user: ${userId}`);
        }
        
        res.json({ 
            success: true, 
            message: 'Chat history cleared successfully.' 
        });
        
    } catch (error) {
        console.error('❌ Error clearing session:', error);
        res.status(500).json({ error: 'Failed to clear session.' });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Unhandled error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
});

// ----------------------------------------------------
// Start Server
// ----------------------------------------------------

app.listen(port, () => {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║   🤖 Gemini Chatbot Backend (Production Ready)       ║
║   ✅ Server running at http://localhost:${port}       ║
║   ✅ Health check: http://localhost:${port}/health    ║
║   📦 Model: ${modelName}                              ║
║   🔒 Security: Enabled                                ║
║   ⚡ Rate limiting: Active                            ║
╚═══════════════════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received. Shutting down gracefully...');
    userSessions.clear();
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 SIGINT received. Shutting down gracefully...');
    userSessions.clear();
    process.exit(0);
});