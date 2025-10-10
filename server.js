// server.js - FIXED VERSION
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { GoogleGenAI } from '@google/genai';
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 3000;

// ----------------------------------------------------
// Production Stability Fixes
// ----------------------------------------------------

app.set('trust proxy', 1); 

// ----------------------------------------------------
// Middleware Configuration
// ----------------------------------------------------

app.use(helmet());

// CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()).filter(Boolean);

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        
        if (process.env.NODE_ENV !== 'production') {
            return callback(null, true);
        }
        
        if (!allowedOrigins || allowedOrigins.length === 0) {
            console.warn('⚠️  WARNING: ALLOWED_ORIGINS not set. Blocking request from:', origin);
            return callback(new Error('CORS not configured'));
        }
        
        if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST'],
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// ✅ FIXED: Rate limiting (ลบ custom keyGenerator ออก)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
    // ✅ ไม่ต้องใส่ keyGenerator เพราะจะใช้ default ที่รองรับ IPv6
});

const chatLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, 
    max: 20, 
    message: { error: 'Too many chat requests, please slow down.' }
    // ✅ ไม่ต้องใส่ keyGenerator
});

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

// Session management
const userSessions = new Map();
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

let sessionStats = {
    created: 0,
    cleared: 0,
    expired: 0,
    messagesProcessed: 0
};

// Clean up old sessions every 10 minutes
setInterval(() => {
    const now = Date.now();
    let expiredCount = 0;
    
    for (const [userId, session] of userSessions.entries()) {
        if (now - session.lastActivity > SESSION_TIMEOUT) {
            userSessions.delete(userId);
            expiredCount++;
            sessionStats.expired++;
        }
    }
    
    if (expiredCount > 0) {
        console.log(`🗑️  Cleaned ${expiredCount} expired sessions. Active: ${userSessions.size}`);
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
            createdAt: Date.now(),
            messageCount: 0
        });
        sessionStats.created++;
        console.log(`✨ Created new session for user: ${userId} (Total active: ${userSessions.size})`);
    } else {
        const session = userSessions.get(userId);
        session.lastActivity = Date.now();
        session.messageCount++;
    }
    
    return userSessions.get(userId).session;
}

// ----------------------------------------------------
// API Endpoints
// ----------------------------------------------------

// Health check
app.get('/health', (req, res) => {
    const memoryUsage = process.memoryUsage();
    
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        activeSessions: userSessions.size,
        stats: sessionStats,
        memory: {
            heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
            heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`
        },
        model: modelName,
        environment: process.env.NODE_ENV || 'development'
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        name: 'Gemini Chatbot API',
        version: '1.0.0',
        status: 'running',
        endpoints: {
            health: 'GET /health',
            chat: 'POST /api/chat/send',
            clear: 'POST /api/chat/clear'
        }
    });
});

// Chat send endpoint (STREAMING)
app.post('/api/chat/send', chatLimiter, async (req, res) => {
    
    res.setHeader('Content-Type', 'text/plain; charset=utf-8'); 
    res.setHeader('Transfer-Encoding', 'chunked');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.status(200); 

    try {
        const { message, userId } = req.body;
        
        if (!userId || typeof userId !== 'string') {
            if (res.headersSent) {
                return res.end(`\n\n[STREAM_ERROR] ⚠️ ERROR: Missing or invalid userId.`);
            }
            return res.status(400).json({ 
                error: 'Missing or invalid userId. Please provide a valid user identifier.' 
            });
        }
        
        const validation = validateMessage(message);
        if (!validation.valid) {
            if (res.headersSent) {
                return res.end(`\n\n[STREAM_ERROR] ⚠️ ERROR: ${validation.error}`);
            }
            return res.status(400).json({ error: validation.error });
        }
        
        console.log(`💬 [${userId}] ${validation.message.substring(0, 50)}${validation.message.length > 50 ? '...' : ''}`);
        
        const chatSession = getUserSession(userId);
        sessionStats.messagesProcessed++;
        
        const responseStream = await chatSession.sendMessageStream({ 
            message: validation.message 
        });
        
        let chunkCount = 0;
        for await (const chunk of responseStream) {
            const chunkText = chunk.text;
            if (chunkText) {
                res.write(chunkText);
                chunkCount++;
            }
        }
        
        console.log(`🤖 [${userId}] Stream complete (${chunkCount} chunks)`);
        res.end();
        
    } catch (error) {
        console.error('❌ Error in /api/chat/send:', error.message);
        
        let errorMessage = 'Failed to get response from AI.';
        let statusCode = 500;
        
        if (error.message?.includes('quota')) {
            errorMessage = 'API quota exceeded. Please try again later.';
            statusCode = 429;
        } else if (error.message?.includes('API key') || error.message?.includes('authentication')) {
            errorMessage = 'Authentication error. Invalid API configuration.';
            statusCode = 401;
        } else if (error.message?.includes('timeout')) {
            errorMessage = 'Request timeout. Please try again.';
            statusCode = 408;
        }

        if (res.headersSent) {
            res.end(`\n\n[STREAM_ERROR] ⚠️ ${errorMessage}`); 
        } else {
            const details = process.env.NODE_ENV === 'development' ? error.message : undefined;
            res.status(statusCode).json({ 
                error: errorMessage,
                details: details
            });
        }
    }
});

// Clear user session endpoint
app.post('/api/chat/clear', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'Missing userId.' });
        }
        
        if (userSessions.has(userId)) {
            userSessions.delete(userId);
            sessionStats.cleared++;
            console.log(`🗑️  Cleared session for user: ${userId}`);
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
    res.status(404).json({ 
        error: 'Endpoint not found',
        path: req.path,
        method: req.method
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Unhandled error:', error);
    
    if (error.message === 'Not allowed by CORS') {
        return res.status(403).json({ error: 'CORS policy violation' });
    }
    
    res.status(500).json({ 
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
});

// ----------------------------------------------------
// Start Server
// ----------------------------------------------------

const host = '0.0.0.0';

const server = app.listen(port, host, () => {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║   🤖 Gemini Chatbot Backend v1.0.0                    ║
║   ✅ Server: http://${host}:${port}                   ║
║   ✅ Environment: ${process.env.NODE_ENV || 'development'}                      ║
║   📦 Model: ${modelName}                              ║
║   🔒 Security: Enabled                                ║
║   ⚡ Rate limiting: Active                            ║
║   🌐 CORS: ${allowedOrigins?.length || 0} origin(s) allowed              ║
╚═══════════════════════════════════════════════════════╝
    `);
    
    if (!allowedOrigins || allowedOrigins.length === 0) {
        console.warn('⚠️  WARNING: ALLOWED_ORIGINS not configured!');
        console.warn('   Set ALLOWED_ORIGINS in environment variables for production.');
    }
});

// ----------------------------------------------------
// Graceful Shutdown
// ----------------------------------------------------

function gracefulShutdown(signal) {
    console.log(`\n🛑 ${signal} received. Shutting down gracefully...`);
    
    server.close(() => {
        console.log('✅ HTTP server closed');
        
        const sessionCount = userSessions.size;
        userSessions.clear();
        console.log(`✅ Cleared ${sessionCount} active sessions`);
        
        console.log('👋 Goodbye!');
        process.exit(0);
    });
    
    setTimeout(() => {
        console.error('⚠️  Forced shutdown after timeout');
        process.exit(1);
    }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error.message);
    console.error(error.stack);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});