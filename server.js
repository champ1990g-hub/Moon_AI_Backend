// server.js
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

// FIX 1: Allow Express to trust proxy headers (Required for Render/Proxies and Rate Limiting)
app.set('trust proxy', 1); 

// ----------------------------------------------------
// Middleware Configuration
// ----------------------------------------------------

// Security headers
app.use(helmet());

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',');

const corsOptions = {
    // FIX 2: Allow all origins if ALLOWED_ORIGINS is not set (for local development)
    origin: allowedOrigins && allowedOrigins.length > 0 ? allowedOrigins : ['*'],
    methods: ['GET', 'POST'],
    credentials: true
};
app.use(cors(corsOptions));

// Body parser
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const chatLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, 
    max: 20, 
    message: { error: 'Too many chat requests, please slow down.' }
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

// Session management - Store sessions per user
const userSessions = new Map();
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

// Clean up old sessions every 10 minutes
setInterval(() => {
    const now = Date.now();
    for (const [userId, session] of userSessions.entries()) {
        if (now - session.lastActivity > SESSION_TIMEOUT) {
            userSessions.delete(userId);
            console.log(`🗑️  Session cleaned for user: ${userId}`);
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

// Chat send endpoint (STREAMING LOGIC)
app.post('/api/chat/send', chatLimiter, async (req, res) => {
    
    // Set headers for Streaming
    res.setHeader('Content-Type', 'text/plain'); 
    res.setHeader('Transfer-Encoding', 'chunked');
    res.status(200); 

    try {
        const { message, userId } = req.body;
        
        if (!userId || typeof userId !== 'string') {
            // If headers are sent, we can't send JSON anymore, just end the stream with an error
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
        
        console.log(`💬 User ${userId}: ${validation.message.substring(0, 50)}...`);
        
        const chatSession = getUserSession(userId);
        
        const responseStream = await chatSession.sendMessageStream({ 
            message: validation.message 
        });
        
        for await (const chunk of responseStream) {
            const chunkText = chunk.text;
            if (chunkText) {
                res.write(chunkText);
            }
        }
        
        console.log(`🤖 AI Response stream finished for user ${userId}`);
        res.end();
        
    } catch (error) {
        console.error('❌ Error in /api/chat/send:', error);
        
        let errorMessage = 'Failed to get full response.';
        if (error.message?.includes('quota')) {
             errorMessage = 'API Quota Exceeded. Please try again later.';
        } else if (error.message?.includes('API key')) {
             errorMessage = 'Authentication error. Invalid API configuration.';
        }

        if (res.headersSent) {
            // FIX 4: Send a structured error message to the stream for client handling
            res.end(`\n\n[STREAM_ERROR] ⚠️ ERROR: ${errorMessage}.`); 
        } else {
            const details = process.env.NODE_ENV === 'development' ? error.message : 'Internal server error';
            
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

// Clear user session endpoint
app.post('/api/chat/clear', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(400).json({ error: 'Missing userId.' });
        }
        
        if (userSessions.has(userId)) {
            userSessions.delete(userId);
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
// Start Server (Production Ready)
// ----------------------------------------------------

const host = '0.0.0.0'; // FIX 3: Ensures binding to the correct interface for Production/Render

app.listen(port, host, () => {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║   🤖 Gemini Chatbot Backend (Production Ready)        ║
║   ✅ Server running at http://${host}:${port}         ║
║   ✅ Health check: http://${host}:${port}/health      ║
║   📦 Model: ${modelName}                              ║
║   🔒 Security: Enabled                                ║
║   ⚡ Rate limiting: Active                             ║
╚═══════════════════════════════════════════════════════╝
    `);
});

// ----------------------------------------------------
// Global Process Error Handling (Ensures process stability)
// ----------------------------------------------------

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error.message, error.stack);
    // Graceful shutdown after uncaught exception
    userSessions.clear();
    process.exit(1); 
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