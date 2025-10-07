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

// Chat send endpoint (STREAMING LOGIC)
app.post('/api/chat/send', chatLimiter, async (req, res) => {
    
    // Set headers for Streaming
    res.setHeader('Content-Type', 'text/plain'); 
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
        
        // Use sendMessageStream
        const responseStream = await chatSession.sendMessageStream({ 
            message: validation.message 
        });
        
        // Loop through the stream and write to the response
        for await (const chunk of responseStream) {
            const chunkText = chunk.text;
            if (chunkText) {
                res.write(chunkText);
            }
        }
        
        console.log(`🤖 AI Response stream finished for user ${userId}`);
        
        // End the response
        res.end();
        
    } catch (error) {
        console.error('❌ Error in /api/chat/send:', error);
        
        // Handle Error: If headers were already sent (streaming started), end the stream with an error message
        if (res.headersSent) {
            let errorMessage = 'Failed to get full response.';
            if (error.message?.includes('quota')) {
                 errorMessage = 'API Quota Exceeded. Please try again later.';
            } else if (error.message?.includes('API key')) {
                 errorMessage = 'Authentication error. Invalid API configuration.';
            }
            res.end(`\n\n⚠️ ERROR: ${errorMessage}`);
        } else {
             // If headers haven't been sent, send a normal JSON error response
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
// Start Server (Fix for Render/Production)
// ----------------------------------------------------

const host = '0.0.0.0'; // Forces the server to bind to all available network interfaces (Required for Render)

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
// Global Process Error Handling (NEW)
// ----------------------------------------------------

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    // Log the error but allow the process to continue running
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error.message, error.stack);
    // Uncaught exceptions are critical. Log and exit gracefully.
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