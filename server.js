const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server, maxPayload: 50 * 1024 * 1024 }); // 50MB лимит

// Конфигурация безопасности
const SECRET_KEY = process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex');
const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(16).toString('hex');
const MAX_MESSAGE_LENGTH = 10000;
const MAX_NICKNAME_LENGTH = 50;
const MAX_ROOM_ID_LENGTH = 100;
const RATE_LIMIT_WINDOW = 60000; // 1 минута
const RATE_LIMIT_MAX_MESSAGES = 30;

// Хранилище комнат
const rooms = new Map();

// Хранение WebSocket соединений по userId
const userConnections = new Map();

// Хранение ников и аватаров пользователей
const userNicknames = new Map();
const userAvatars = new Map();

// Rate limiting по IP
const rateLimitMap = new Map();

// Очистка старых файловых чанков
const fileChunks = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [key, chunk] of fileChunks.entries()) {
        if (chunk.timestamp && now - chunk.timestamp > 300000) { // 5 минут
            fileChunks.delete(key);
        }
    }
}, 60000);

// Функции безопасности
function sanitizeInput(input, maxLength = 1000) {
    if (typeof input !== 'string') return '';
    return input
        .trim()
        .substring(0, maxLength)
        .replace(/[<>]/g, '') // Базовая защита от XSS
        .replace(/[\x00-\x1F\x7F]/g, ''); // Удаляем управляющие символы
}

function validateRoomId(roomId) {
    if (!roomId || typeof roomId !== 'string') return false;
    if (roomId.length > MAX_ROOM_ID_LENGTH) return false;
    return /^[a-zA-Z0-9_-]+$/.test(roomId); // Только буквы, цифры, дефис и подчеркивание
}

function validateNickname(nickname) {
    if (!nickname || typeof nickname !== 'string') return false;
    if (nickname.length > MAX_NICKNAME_LENGTH) return false;
    return nickname.trim().length > 0;
}

function validateAvatar(avatar) {
    if (!avatar) return true; // Аватар опционален
    if (typeof avatar !== 'string') return false;
    if (avatar.length > 500) return false;
    return /^https?:\/\/.+/.test(avatar); // Должен быть валидный URL
}

function checkRateLimit(ip) {
    const now = Date.now();
    const userLimit = rateLimitMap.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW };
    
    if (now > userLimit.resetTime) {
        userLimit.count = 0;
        userLimit.resetTime = now + RATE_LIMIT_WINDOW;
    }
    
    userLimit.count++;
    rateLimitMap.set(ip, userLimit);
    
    if (userLimit.count > RATE_LIMIT_MAX_MESSAGES) {
        return false;
    }
    return true;
}

function getClientIP(ws) {
    return ws._socket?.remoteAddress || 'unknown';
}

// Шифрование данных (опционально, для чувствительных данных)
function encryptData(data, key = SECRET_KEY) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.substring(0, 32), 'hex'), iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptData(encryptedData, key = SECRET_KEY) {
    try {
        const parts = encryptedData.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key.substring(0, 32), 'hex'), iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (e) {
        return null;
    }
}

wss.on('connection', (ws) => {
    const clientIP = getClientIP(ws);
    console.log(`Новое подключение с IP: ${clientIP}`);
    
    let currentUserId = null;
    let currentRoomId = null;
    let isAuthenticated = false;
    
    // Проверка rate limit при подключении
    if (!checkRateLimit(clientIP)) {
        ws.close(1008, 'Rate limit exceeded');
        return;
    }
    
    ws.on('message', (message) => {
        try {
            // Проверка rate limit для каждого сообщения
            if (!checkRateLimit(clientIP)) {
                ws.send(JSON.stringify({ 
                    type: 'error', 
                    message: 'Превышен лимит сообщений. Подождите немного.' 
                }));
                return;
            }
            
            // Проверяем, является ли сообщение строкой (JSON) или бинарными данными
            if (typeof message === 'string') {
                // Проверка размера сообщения
                if (message.length > MAX_MESSAGE_LENGTH * 10) {
                    ws.send(JSON.stringify({ 
                        type: 'error', 
                        message: 'Сообщение слишком большое' 
                    }));
                    return;
                }
                
                let data;
                try {
                    data = JSON.parse(message);
                } catch (e) {
                    ws.send(JSON.stringify({ 
                        type: 'error', 
                        message: 'Неверный формат сообщения' 
                    }));
                    return;
                }
                
                // Валидация типа сообщения
                if (!data.type || typeof data.type !== 'string') {
                    ws.send(JSON.stringify({ 
                        type: 'error', 
                        message: 'Не указан тип сообщения' 
                    }));
                    return;
                }
                
                console.log(`Получено сообщение от ${clientIP}:`, data.type);
                
                switch(data.type) {
                    case 'join':
                        if (isAuthenticated) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Вы уже подключены к комнате' 
                            }));
                            break;
                        }
                        const result = handleJoin(ws, data, clientIP);
                        if (result) {
                            currentUserId = result.userId;
                            currentRoomId = result.roomId;
                            isAuthenticated = true;
                            userConnections.set(currentUserId, ws);
                            
                            // Сохраняем ник и аватар пользователя
                            if (data.nickname) {
                                userNicknames.set(currentUserId, sanitizeInput(data.nickname, MAX_NICKNAME_LENGTH));
                            }
                            if (data.avatar) {
                                userAvatars.set(currentUserId, sanitizeInput(data.avatar, 500));
                            }
                        }
                        break;
                    case 'offer':
                    case 'answer':
                    case 'candidate':
                        if (!isAuthenticated || !currentUserId) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Необходимо подключиться к комнате' 
                            }));
                            break;
                        }
                        // Валидация WebRTC данных
                        if (data.type === 'offer' || data.type === 'answer') {
                            if (!data.offer && !data.answer) {
                                ws.send(JSON.stringify({ 
                                    type: 'error', 
                                    message: 'Неверные данные WebRTC' 
                                }));
                                break;
                            }
                        }
                        forwardToPeer(data, currentUserId);
                        break;
                    case 'message':
                        if (!isAuthenticated || !currentUserId) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Необходимо подключиться к комнате' 
                            }));
                            break;
                        }
                        // Валидация текста сообщения
                        if (!data.text || typeof data.text !== 'string') {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Текст сообщения обязателен' 
                            }));
                            break;
                        }
                        if (data.text.length > MAX_MESSAGE_LENGTH) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: `Сообщение слишком длинное (макс. ${MAX_MESSAGE_LENGTH} символов)` 
                            }));
                            break;
                        }
                        forwardMessage(data, currentUserId);
                        break;
                    case 'file':
                        if (!isAuthenticated || !currentUserId) {
                            ws.send(JSON.stringify({ 
                                type: 'error', 
                                message: 'Необходимо подключиться к комнате' 
                            }));
                            break;
                        }
                        forwardFile(data);
                        break;
                    case 'leave':
                        if (currentUserId && currentRoomId) {
                            handleLeave({ userId: currentUserId, roomId: currentRoomId });
                        }
                        break;
                    default:
                        ws.send(JSON.stringify({ 
                            type: 'error', 
                            message: 'Неизвестный тип сообщения' 
                        }));
                }
            } else {
                // Обработка бинарных данных (чанков файла)
                if (!isAuthenticated || !currentUserId) {
                    ws.send(JSON.stringify({ 
                        type: 'error', 
                        message: 'Необходимо подключиться к комнате' 
                    }));
                    return;
                }
                handleBinaryMessage(message, ws, currentUserId);
            }
        } catch (error) {
            console.error('Ошибка обработки сообщения:', error);
            try {
                ws.send(JSON.stringify({ 
                    type: 'error', 
                    message: 'Ошибка обработки запроса' 
                }));
            } catch (e) {
                // Соединение уже закрыто
            }
        }
    });
    
    ws.on('error', (error) => {
        console.error('WebSocket ошибка:', error);
    });
    
    ws.on('close', () => {
        console.log(`Клиент отключился: ${clientIP}`);
        
        // Очистка при отключении
        if (currentUserId && currentRoomId) {
            handleUserDisconnect(currentUserId, currentRoomId);
            userConnections.delete(currentUserId);
            userNicknames.delete(currentUserId);
            userAvatars.delete(currentUserId);
        }
        
        // Очистка rate limit через время
        setTimeout(() => {
            rateLimitMap.delete(clientIP);
        }, RATE_LIMIT_WINDOW);
    });
    
    // Отправляем ping для проверки соединения
    const pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.ping();
        } else {
            clearInterval(pingInterval);
        }
    }, 30000);
    
    ws.on('pong', () => {
        // Клиент ответил на ping
    });
    
    ws.on('close', () => {
        clearInterval(pingInterval);
    });
});

function handleBinaryMessage(data, ws, senderId) {
    try {
        // Проверка размера данных
        if (data.length > 50 * 1024 * 1024) { // 50MB максимум
            ws.send(JSON.stringify({ 
                type: 'error', 
                message: 'Файл слишком большой' 
            }));
            return;
        }
        
        // Первые 4 байта - длина metadata
        if (data.length < 4) {
            ws.send(JSON.stringify({ 
                type: 'error', 
                message: 'Неверный формат бинарных данных' 
            }));
            return;
        }
        
        const metadataLength = data.readUInt32BE(0);
        if (metadataLength > 10000 || data.length < 4 + metadataLength) {
            ws.send(JSON.stringify({ 
                type: 'error', 
                message: 'Неверный формат метаданных' 
            }));
            return;
        }
        
        const metadataString = data.toString('utf8', 4, 4 + metadataLength);
        let metadata;
        try {
            metadata = JSON.parse(metadataString);
        } catch (e) {
            ws.send(JSON.stringify({ 
                type: 'error', 
                message: 'Ошибка парсинга метаданных' 
            }));
            return;
        }
        
        // Валидация метаданных
        if (!metadata.fileId || !metadata.senderId || metadata.senderId !== senderId) {
            ws.send(JSON.stringify({ 
                type: 'error', 
                message: 'Неверные метаданные файла' 
            }));
            return;
        }
        
        // Остальное - данные файла
        const fileData = data.slice(4 + metadataLength);
        
        switch(metadata.type) {
            case 'file_chunk':
                // Сохраняем чанк с временной меткой
                const key = `${metadata.fileId}_${metadata.chunkIndex}`;
                fileChunks.set(key, {
                    data: fileData,
                    metadata: metadata,
                    timestamp: Date.now()
                });
                
                // Проверяем, собраны ли все чанки
                checkAndForwardCompleteFile(metadata, ws);
                break;
                
            case 'file_complete':
                // Файл полностью отправлен
                forwardCompleteFile(metadata, ws);
                break;
        }
    } catch (error) {
        console.error('Ошибка обработки бинарного сообщения:', error);
        try {
            ws.send(JSON.stringify({ 
                type: 'error', 
                message: 'Ошибка обработки файла' 
            }));
        } catch (e) {
            // Соединение закрыто
        }
    }
}

function checkAndForwardCompleteFile(metadata, ws) {
    const { fileId, totalChunks, targetUserId, senderId, fileName, fileType, fileSize, preview } = metadata;
    
    // Проверяем, все ли чанки получены
    let allChunksReceived = true;
    const chunks = [];
    
    for (let i = 0; i < totalChunks; i++) {
        const key = `${fileId}_${i}`;
        if (!fileChunks.has(key)) {
            allChunksReceived = false;
            break;
        }
        chunks.push(fileChunks.get(key).data);
    }
    
    if (allChunksReceived) {
        // Собираем все чанки в один буфер
        const totalSize = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
        const completeFile = Buffer.concat(chunks, totalSize);
        
        // Очищаем чанки из памяти
        for (let i = 0; i < totalChunks; i++) {
            fileChunks.delete(`${fileId}_${i}`);
        }
        
        // Отправляем получателю
        const targetWs = userConnections.get(targetUserId);
        if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            // Для изображений отправляем preview и данные
            if (fileType.startsWith('image/')) {
                targetWs.send(JSON.stringify({
                    type: 'file',
                    fileId: fileId,
                    senderId: senderId,
                    fileName: fileName,
                    fileType: fileType,
                    fileSize: fileSize,
                    preview: preview,
                    isImage: true
                }));
                
                // Отправляем бинарные данные отдельным сообщением
                sendBinaryFile(targetWs, {
                    fileId: fileId,
                    data: completeFile,
                    type: 'image_data'
                });
            } else {
                // Для обычных файлов
                targetWs.send(JSON.stringify({
                    type: 'file',
                    fileId: fileId,
                    senderId: senderId,
                    fileName: fileName,
                    fileType: fileType,
                    fileSize: fileSize,
                    isImage: false
                }));
                
                sendBinaryFile(targetWs, {
                    fileId: fileId,
                    data: completeFile,
                    fileName: fileName,
                    type: 'file_data'
                });
            }
        }
    }
}

function forwardCompleteFile(metadata, ws) {
    const { fileId, targetUserId, senderId, fileName, fileType, fileSize, preview } = metadata;
    
    const targetWs = userConnections.get(targetUserId);
    if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({
            type: 'file_complete',
            fileId: fileId,
            senderId: senderId,
            fileName: fileName,
            fileType: fileType,
            fileSize: fileSize,
            preview: preview
        }));
    }
}

function sendBinaryFile(ws, data) {
    // Формируем бинарное сообщение: [длина metadata][metadata][данные]
    const metadata = {
        type: data.type,
        fileId: data.fileId,
        fileName: data.fileName
    };
    
    const metadataString = JSON.stringify(metadata);
    const metadataBuffer = Buffer.from(metadataString, 'utf8');
    
    const header = Buffer.alloc(4);
    header.writeUInt32BE(metadataBuffer.length, 0);
    
    const message = Buffer.concat([header, metadataBuffer, data.data]);
    
    ws.send(message, { binary: true });
}

function handleJoin(ws, data, clientIP) {
    // Валидация входных данных
    let { roomId, maxUsers, nickname, avatar } = data;
    
    // Валидация roomId
    if (!roomId || typeof roomId !== 'string') {
        ws.send(JSON.stringify({ 
            type: 'error', 
            message: 'Укажите название комнаты' 
        }));
        return null;
    }
    
    roomId = sanitizeInput(roomId, MAX_ROOM_ID_LENGTH);
    if (!validateRoomId(roomId)) {
        ws.send(JSON.stringify({ 
            type: 'error', 
            message: 'Название комнаты может содержать только буквы, цифры, дефис и подчеркивание' 
        }));
        return null;
    }
    
    // Валидация maxUsers
    maxUsers = parseInt(maxUsers) || 4;
    if (isNaN(maxUsers) || maxUsers < 2 || maxUsers > 6) {
        maxUsers = 4; // Значение по умолчанию
    }
    
    // Валидация nickname
    nickname = nickname ? sanitizeInput(nickname, MAX_NICKNAME_LENGTH) : 'Участник';
    if (!validateNickname(nickname)) {
        nickname = 'Участник';
    }
    
    // Валидация avatar
    avatar = avatar ? sanitizeInput(avatar, 500) : null;
    if (avatar && !validateAvatar(avatar)) {
        avatar = null;
    }
    
    let room = rooms.get(roomId);
    const isNewRoom = !room;
    
    // Если комната не существует, создаем (оптимизированное создание)
    if (!room) {
        room = {
            id: roomId,
            maxUsers: maxUsers,
            users: [],
            userData: new Map(),
            creationTime: Date.now(),
            ready: true // Флаг готовности комнаты
        };
        rooms.set(roomId, room);
        console.log(`✅ Создана комната ${roomId} на ${room.maxUsers} человек (IP: ${clientIP})`);
    }
    
    // Проверяем количество пользователей
    if (room.users.length >= room.maxUsers) {
        ws.send(JSON.stringify({ 
            type: 'error', 
            message: 'Комната переполнена' 
        }));
        return null;
    }
    
    // Создаем пользователя
    const userId = generateUserId();
    const user = {
        id: userId,
        ws: ws,
        nickname: nickname,
        avatar: avatar,
        joinTime: Date.now(),
        ip: clientIP
    };
    
    room.users.push(user);
    
    // Сохраняем данные пользователя в комнате
    room.userData.set(userId, {
        nickname: user.nickname,
        avatar: user.avatar
    });
    
    console.log(`👤 Пользователь ${userId} (${user.nickname}) присоединился к комнате ${roomId}. Всего: ${room.users.length}/${room.maxUsers}`);
    
    // Собираем ники и аватары всех пользователей в комнате (оптимизировано)
    const nicknames = {};
    const avatars = {};
    for (const u of room.users) {
        nicknames[u.id] = u.nickname;
        avatars[u.id] = u.avatar;
    }
    
    // Отправляем подтверждение новому пользователю (оптимизированная отправка)
    const joinResponse = {
        type: 'joined',
        userId: userId,
        users: room.users.map(u => u.id),
        roomId: roomId,
        maxUsers: room.maxUsers,
        nicknames: nicknames,
        avatars: avatars,
        isNewRoom: isNewRoom // Информируем клиента, что комната только что создана
    };
    
    // Отправляем ответ немедленно для быстрого подключения
    ws.send(JSON.stringify(joinResponse));
    
    // Уведомляем других о новом пользователе (асинхронно, не блокируя ответ)
    setImmediate(() => {
        broadcastToRoom(roomId, {
            type: 'user_joined',
            userId: userId,
            users: room.users.map(u => u.id),
            nickname: user.nickname,
            avatar: user.avatar
        }, ws);
    });
    
    return { userId, roomId };
}

function forwardToPeer(data, senderId) {
    const { targetUserId, ...message } = data;
    
    // Валидация targetUserId
    if (!targetUserId || typeof targetUserId !== 'string') {
        return;
    }
    
    // Проверка, что отправитель существует
    if (!userConnections.has(senderId)) {
        return;
    }
    
    const targetWs = userConnections.get(targetUserId);
    if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        try {
            targetWs.send(JSON.stringify(message));
        } catch (error) {
            console.error(`Ошибка отправки сообщения пользователю ${targetUserId}:`, error);
        }
    } else {
        console.log(`Пользователь ${targetUserId} не найден или не в сети`);
    }
}

function forwardMessage(data, senderId) {
    const { targetUserId, text, senderNickname, senderAvatar } = data;
    
    // Валидация
    if (!targetUserId || typeof targetUserId !== 'string') {
        return;
    }
    
    if (!text || typeof text !== 'string' || text.length > MAX_MESSAGE_LENGTH) {
        return;
    }
    
    // Санитизация данных перед отправкой
    const sanitizedNickname = senderNickname ? sanitizeInput(senderNickname, MAX_NICKNAME_LENGTH) : 'Пользователь';
    const sanitizedAvatar = senderAvatar ? sanitizeInput(senderAvatar, 500) : null;
    const sanitizedText = sanitizeInput(text, MAX_MESSAGE_LENGTH);
    
    const targetWs = userConnections.get(targetUserId);
    if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        try {
            targetWs.send(JSON.stringify({
                type: 'message',
                text: sanitizedText,
                senderId: senderId,
                senderNickname: sanitizedNickname,
                senderAvatar: sanitizedAvatar
            }));
        } catch (error) {
            console.error(`Ошибка отправки сообщения пользователю ${targetUserId}:`, error);
        }
    }
}

function forwardFile(data) {
    const { targetUserId, fileId, senderId, fileName, fileType, fileSize, preview, chunks } = data;
    
    const targetWs = userConnections.get(targetUserId);
    if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({
            type: 'file_info',
            fileId: fileId,
            senderId: senderId,
            fileName: fileName,
            fileType: fileType,
            fileSize: fileSize,
            preview: preview,
            chunks: chunks
        }));
    }
}

function handleLeave(data) {
    const { roomId, userId } = data;
    handleUserDisconnect(userId, roomId);
}

function handleUserDisconnect(userId, roomId) {
    const room = rooms.get(roomId);
    
    if (room) {
        const userIndex = room.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            const user = room.users[userIndex];
            room.users.splice(userIndex, 1);
            room.userData.delete(userId);
            
            console.log(`Пользователь ${userId} (${user.nickname}) покинул комнату ${roomId}. Осталось: ${room.users.length}`);
            
            // Уведомляем остальных
            broadcastToRoom(roomId, {
                type: 'user_left',
                userId: userId,
                users: room.users.map(u => u.id)
            });
            
            // Если комната пуста, удаляем её через некоторое время
            if (room.users.length === 0) {
                setTimeout(() => {
                    if (rooms.has(roomId) && rooms.get(roomId).users.length === 0) {
                        rooms.delete(roomId);
                        console.log(`Комната ${roomId} удалена за неактивностью`);
                    }
                }, 60000); // Удаляем через минуту
            }
        }
    }
}

function broadcastToRoom(roomId, message, excludeWs = null) {
    const room = rooms.get(roomId);
    if (room) {
        try {
            const messageStr = JSON.stringify(message);
            const failedUsers = [];
            
            room.users.forEach(user => {
                if (user.ws !== excludeWs && user.ws.readyState === WebSocket.OPEN) {
                    try {
                        user.ws.send(messageStr);
                    } catch (error) {
                        console.error(`Ошибка отправки broadcast пользователю ${user.id}:`, error);
                        failedUsers.push(user.id);
                    }
                }
            });
            
            // Удаляем пользователей с неработающими соединениями
            if (failedUsers.length > 0) {
                failedUsers.forEach(userId => {
                    const userIndex = room.users.findIndex(u => u.id === userId);
                    if (userIndex !== -1) {
                        room.users.splice(userIndex, 1);
                        room.userData.delete(userId);
                        userConnections.delete(userId);
                    }
                });
            }
        } catch (error) {
            console.error('Ошибка broadcast:', error);
        }
    }
}

function generateUserId() {
    return 'user_' + Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
}

// Очистка старых комнат
setInterval(() => {
    const now = Date.now();
    for (const [roomId, room] of rooms.entries()) {
        if (room.users.length === 0 && now - room.creationTime > 3600000) {
            rooms.delete(roomId);
            console.log(`Комната ${roomId} удалена (старая)`);
        }
    }
}, 300000); // Проверка каждые 5 минут

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Сигнальный сервер запущен на порту ${PORT}`);
    console.log(`WebSocket URL: wss://${process.env.RENDER_EXTERNAL_HOSTNAME || 'localhost'}:${PORT}`);
});