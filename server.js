// server.js - Production Ready Version (FINAL)
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { GoogleGenAI } from '@google/genai';
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 3000;

// ----------------------------------------------------
// Production Configuration
// ----------------------------------------------------

app.set('trust proxy', 1);

// ----------------------------------------------------
// Middleware Configuration
// ----------------------------------------------------

// Security headers
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration - อนุญาตทุก origin
app.use(cors({
    origin: true, // อนุญาตทุก origin
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors());

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // เพิ่ม limit เป็น 200 requests
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const chatLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // เพิ่ม limit เป็น 30 requests
    message: { error: 'Too many chat requests, please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/', apiLimiter);

// ----------------------------------------------------
// Gemini Client Setup
// ----------------------------------------------------

console.log('🔑 Initializing Gemini AI with provided API key...');

if (!process.env.GEMINI_API_KEY) {
    console.error('❌ GEMINI_API_KEY is not set in environment variables.');
    process.exit(1);
}

// ตรวจสอบว่า API Key ถูกต้อง (ไม่ใช่ placeholder)
if (process.env.GEMINI_API_KEY.includes('your_actual_gemini_api_key_here') || 
    process.env.GEMINI_API_KEY.length < 10) {
    console.error('❌ Invalid GEMINI_API_KEY. Please check your .env file.');
    process.exit(1);
}

const ai = new GoogleGenAI({ 
    apiKey: process.env.GEMINI_API_KEY 
});

const modelName = process.env.GEMINI_MODEL || "gemini-2.5-flash";

console.log(`✅ Gemini AI initialized with model: ${modelName}`);

// Session management
const userSessions = new Map();
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

// Session statistics
let sessionStats = {
    created: 0,
    cleared: 0,
    expired: 0,
    messagesProcessed: 0,
    errors: 0
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
        const chatSession = ai.chats.create({ 
            model: modelName,
            generationConfig: {
                temperature: 0.7,
                topK: 40,
                topP: 0.95,
            }
        });
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

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        name: 'Gemini Chatbot API',
        version: '2.0.0',
        status: 'ACTIVE',
        environment: process.env.NODE_ENV || 'development',
        timestamp: new Date().toISOString(),
        model: modelName,
        endpoints: {
            health: 'GET /health',
            test: 'GET /api/test',
            chat: 'POST /api/chat/send',
            clear: 'POST /api/chat/clear',
            sessionInfo: 'GET /api/session-info'
        },
        message: '🚀 Server is running successfully with your API key!'
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    const memoryUsage = process.memoryUsage();
    
    res.json({ 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        memory: {
            heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
            heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
            rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`
        },
        sessions: {
            active: userSessions.size,
            stats: sessionStats
        },
        model: modelName,
        environment: process.env.NODE_ENV || 'development'
    });
});

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({
        success: true,
        message: '✅ API is working perfectly!',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        model: modelName,
        cors: 'ENABLED',
        rate_limiting: 'ACTIVE'
    });
});

// Test POST endpoint
app.post('/api/test-post', (req, res) => {
    res.json({
        success: true,
        message: '✅ POST requests are working!',
        received_data: req.body,
        timestamp: new Date().toISOString()
    });
});

// Chat send endpoint (STREAMING)
app.post('/api/chat/send', chatLimiter, async (req, res) => {
    // Set headers for streaming
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Transfer-Encoding', 'chunked');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Access-Control-Allow-Origin', '*');

    try {
        const { message, userId = 'default-user' } = req.body;
        
        // Validate userId
        if (!userId || typeof userId !== 'string') {
            res.write('ERROR: Invalid user ID\n');
            return res.end();
        }
        
        // Validate message
        const validation = validateMessage(message);
        if (!validation.valid) {
            res.write(`ERROR: ${validation.error}\n`);
            return res.end();
        }
        
        const cleanUserId = userId.trim();
        console.log(`💬 [${cleanUserId}] Request: ${validation.message.substring(0, 100)}${validation.message.length > 100 ? '...' : ''}`);
        
        // Get or create user session
        const chatSession = getUserSession(cleanUserId);
        sessionStats.messagesProcessed++;
        
        // Send message and stream response
        console.log(`📡 [${cleanUserId}] Streaming response from Gemini...`);
        const responseStream = await chatSession.sendMessageStream({ 
            message: validation.message 
        });
        
        let chunkCount = 0;
        let fullResponse = '';
        
        for await (const chunk of responseStream) {
            const chunkText = chunk.text;
            if (chunkText) {
                res.write(chunkText);
                fullResponse += chunkText;
                chunkCount++;
            }
        }
        
        console.log(`✅ [${cleanUserId}] Stream completed (${chunkCount} chunks, ${fullResponse.length} characters)`);
        res.end();
        
    } catch (error) {
        console.error('❌ Chat error:', error.message);
        sessionStats.errors++;
        
        let errorMessage = 'Failed to get response from AI. Please try again.';
        
        // Handle specific error types
        if (error.message?.includes('quota')) {
            errorMessage = 'API quota exceeded. Please try again later.';
        } else if (error.message?.includes('API key') || error.message?.includes('authentication')) {
            errorMessage = 'Authentication error. Please check API configuration.';
        } else if (error.message?.includes('timeout')) {
            errorMessage = 'Request timeout. Please try again.';
        } else if (error.message?.includes('rate limit')) {
            errorMessage = 'Rate limit exceeded. Please slow down.';
        } else if (error.message?.includes('model')) {
            errorMessage = 'Model configuration error. Please check model name.';
        }
        
        res.write(`\n🚫 ERROR: ${errorMessage}\n`);
        res.end();
    }
});

// Clear user session endpoint
app.post('/api/chat/clear', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(400).json({ 
                success: false, 
                error: 'User ID is required.' 
            });
        }
        
        const cleanUserId = userId.trim();
        let cleared = false;
        
        if (userSessions.has(cleanUserId)) {
            userSessions.delete(cleanUserId);
            sessionStats.cleared++;
            cleared = true;
            console.log(`🗑️  Cleared session for user: ${cleanUserId}`);
        }
        
        res.json({ 
            success: true, 
            cleared: cleared,
            message: cleared ? 'Chat history cleared successfully.' : 'No active session found.',
            activeSessions: userSessions.size
        });
        
    } catch (error) {
        console.error('❌ Error clearing session:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to clear session.' 
        });
    }
});

// Get session info endpoint
app.get('/api/session-info', (req, res) => {
    const sessions = {};
    
    for (const [userId, session] of userSessions.entries()) {
        sessions[userId] = {
            lastActivity: new Date(session.lastActivity).toISOString(),
            messageCount: session.messageCount,
            age: Math.round((Date.now() - session.createdAt) / 1000) + 's'
        };
    }
    
    res.json({
        success: true,
        totalSessions: userSessions.size,
        sessions: sessions,
        stats: sessionStats
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        success: false,
        error: 'Endpoint not found',
        path: req.path,
        method: req.method,
        availableEndpoints: {
            root: 'GET /',
            health: 'GET /health',
            test: 'GET /api/test',
            testPost: 'POST /api/test-post',
            chat: 'POST /api/chat/send',
            clear: 'POST /api/chat/clear',
            sessionInfo: 'GET /api/session-info'
        }
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error handler:', error);
    
    res.status(500).json({ 
        success: false,
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? undefined : error.message
    });
});

// ----------------------------------------------------
// Start Server
// ----------------------------------------------------

const host = '0.0.0.0';

const server = app.listen(port, host, () => {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║   🤖 GEMINI CHATBOT BACKEND v2.0.0                   ║
║   🚀 STATUS: FULLY OPERATIONAL                       ║
║   ✅ Server: http://${host}:${port}                   ║
║   ✅ Environment: ${process.env.NODE_ENV || 'development'}                      ║
║   📦 Model: ${modelName}                              ║
║   🔑 API Key: ✅ CONFIGURED                          ║
║   🌐 CORS: ✅ ALL ORIGINS ALLOWED                    ║
║   ⚡ Rate Limiting: ACTIVE                           ║
║   🔒 Security: ENABLED                               ║
╚═══════════════════════════════════════════════════════╝
    `);
    
    console.log('\n📋 Available Endpoints:');
    console.log('   GET  /              - Server info');
    console.log('   GET  /health        - Health check');
    console.log('   GET  /api/test      - Basic test');
    console.log('   POST /api/test-post - POST test');
    console.log('   POST /api/chat/send - Chat streaming');
    console.log('   POST /api/chat/clear- Clear session');
    console.log('   GET  /api/session-info - Debug info\n');
    
    console.log('🎯 Ready to accept requests from any origin!');
});

// ----------------------------------------------------
// Process Handlers
// ----------------------------------------------------

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise);
    console.error('   Reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

function gracefulShutdown(signal) {
    console.log(`\n🛑 ${signal} received. Shutting down gracefully...`);
    
    server.close(() => {
        console.log('✅ HTTP server closed');
        console.log(`✅ Cleared ${userSessions.size} active sessions`);
        console.log('👋 Server shutdown complete');
        process.exit(0);
    });
    
    setTimeout(() => {
        console.error('⚠️  Forced shutdown after timeout');
        process.exit(1);
    }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));