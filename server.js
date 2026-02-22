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

// Хранилище комнат
const rooms = new Map();

// Хранение WebSocket соединений по userId
const userConnections = new Map();

// Хранение пользователей и сессий (упрощённые аккаунты в памяти)
// userId -> { id, username, passwordHash }
const users = new Map();
// username -> userId
const usernameIndex = new Map();
// authToken -> userId
const authTokens = new Map();

// Хранение ников и аватаров пользователей
const userNicknames = new Map();
const userAvatars = new Map();

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
    return crypto.randomBytes(24).toString('hex');
}

// Простая регистрация
app.post('/register', (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
        return res.status(400).json({ error: 'Укажите логин и пароль' });
    }

    if (usernameIndex.has(username)) {
        return res.status(409).json({ error: 'Такой логин уже занят' });
    }

    const userId = generateUserId();
    const passwordHash = hashPassword(password);

    const user = { id: userId, username, passwordHash };
    users.set(userId, user);
    usernameIndex.set(username, userId);

    const token = generateToken();
    authTokens.set(token, userId);

    return res.json({ userId, username, token });
});

// Простой логин
app.post('/login', (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
        return res.status(400).json({ error: 'Укажите логин и пароль' });
    }

    const userId = usernameIndex.get(username);
    if (!userId) {
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    const user = users.get(userId);
    if (!user || user.passwordHash !== hashPassword(password)) {
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    const token = generateToken();
    authTokens.set(token, userId);

    return res.json({ userId, username, token });
});

wss.on('connection', (ws) => {
    console.log('Новое подключение');
    let currentUserId = null;
    let currentRoomId = null;
    
    ws.on('message', (message) => {
        try {
            // Проверяем, является ли сообщение строкой (JSON) или бинарными данными
            if (typeof message === 'string') {
                const data = JSON.parse(message);
                console.log('Получено сообщение:', data.type);
                
                switch(data.type) {
                    case 'join':
                        const result = handleJoin(ws, data);
                        if (result) {
                            currentUserId = result.userId;
                            currentRoomId = result.roomId;
                            userConnections.set(currentUserId, ws);
                            
                            // Сохраняем ник и аватар пользователя
                            if (data.nickname) {
                                userNicknames.set(currentUserId, data.nickname);
                            }
                            if (data.avatar) {
                                userAvatars.set(currentUserId, data.avatar);
                            }
                        }
                        break;
                    case 'offer':
                    case 'answer':
                    case 'candidate':
                        forwardToPeer(data);
                        break;
                    case 'message':
                        forwardMessage(data);
                        break;
                    case 'file':
                        forwardFile(data);
                        break;
                    case 'leave':
                        handleLeave(data);
                        break;
                }
            } else {
                // Обработка бинарных данных (чанков файла)
                handleBinaryMessage(message, ws);
            }
        } catch (error) {
            console.error('Ошибка обработки сообщения:', error);
        }
    });
    
    ws.on('close', () => {
        console.log('Клиент отключился');
        
        // Очистка при отключении
        if (currentUserId && currentRoomId) {
            handleUserDisconnect(currentUserId, currentRoomId);
            userConnections.delete(currentUserId);
            userNicknames.delete(currentUserId);
            userAvatars.delete(currentUserId);
        }
    });
    
    // Отправляем ping для проверки соединения
    const pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.ping();
        }
    }, 30000);
    
    ws.on('pong', () => {
        // Клиент ответил на ping
    });
    
    ws.on('close', () => {
        clearInterval(pingInterval);
    });
});

// Хранилище для собираемых файловых чанков
const fileChunks = new Map();

function handleBinaryMessage(data, ws) {
    try {
        // Первые 4 байта - длина metadata
        const metadataLength = data.readUInt32BE(0);
        const metadataString = data.toString('utf8', 4, 4 + metadataLength);
        const metadata = JSON.parse(metadataString);
        
        // Остальное - данные файла
        const fileData = data.slice(4 + metadataLength);
        
        switch(metadata.type) {
            case 'file_chunk':
                // Сохраняем чанк
                const key = `${metadata.fileId}_${metadata.chunkIndex}`;
                fileChunks.set(key, {
                    data: fileData,
                    metadata: metadata
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

function handleJoin(ws, data) {
    const { roomId, maxUsers, nickname, avatar, authToken } = data;
    
    // Проверяем токен авторизации
    if (!authToken || !authTokens.has(authToken)) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Не авторизовано. Сначала войдите в аккаунт.'
        }));
        return null;
    }

    const userId = authTokens.get(authToken);
    const user = users.get(userId);
    if (!user) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Пользователь не найден. Перезайдите в аккаунт.'
        }));
        return null;
    }

    // Проверяем наличие комнаты
    if (!roomId) {
        ws.send(JSON.stringify({ 
            type: 'error', 
            message: 'Укажите название комнаты' 
        }));
        return null;
    }
    
    let room = rooms.get(roomId);
    
    // Если комната не существует, создаем
    if (!room) {
        room = {
            id: roomId,
            maxUsers: Math.min(maxUsers || 6, 6), // Максимум 6
            users: [],
            userData: new Map(), // Храним ники и аватары пользователей в комнате
            creationTime: Date.now()
        };
        rooms.set(roomId, room);
        console.log(`Создана комната ${roomId} на ${room.maxUsers} человек`);
    }
    
    // Проверяем количество пользователей
    if (room.users.length >= room.maxUsers) {
        ws.send(JSON.stringify({ 
            type: 'error', 
            message: 'Комната переполнена' 
        }));
        return null;
    }
    
    // Проверяем, не находится ли пользователь уже в комнате
    const alreadyInRoom = room.users.find(u => u.id === userId);
    if (alreadyInRoom) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Вы уже находитесь в этой комнате'
        }));
        return null;
    }

    // Создаем пользователя в рамках комнаты
    const user = {
        id: userId,
        ws: ws,
        nickname: nickname || user.username || 'Участник',
        avatar: avatar || null,
        joinTime: Date.now()
    };
    
    room.users.push(user);
    
    // Сохраняем данные пользователя в комнате
    room.userData.set(userId, {
        nickname: user.nickname,
        avatar: user.avatar
    });
    
    console.log(`Пользователь ${userId} (${user.nickname}) присоединился к комнате ${roomId}. Всего: ${room.users.length}/${room.maxUsers}`);
    
    // Собираем ники и аватары всех пользователей в комнате
    const nicknames = {};
    const avatars = {};
    room.users.forEach(u => {
        nicknames[u.id] = u.nickname;
        avatars[u.id] = u.avatar;
    });
    
    // Отправляем подтверждение новому пользователю
    ws.send(JSON.stringify({
        type: 'joined',
        userId: userId,
        users: room.users.map(u => u.id),
        roomId: roomId,
        maxUsers: room.maxUsers,
        nicknames: nicknames,
        avatars: avatars
    }));
    
    // Уведомляем других о новом пользователе с его ником и аватаром
    broadcastToRoom(roomId, {
        type: 'user_joined',
        userId: userId,
        users: room.users.map(u => u.id),
        nickname: user.nickname,
        avatar: user.avatar
    }, ws);
    
    return { userId, roomId };
}

function forwardToPeer(data) {
    const { targetUserId, ...message } = data;
    
    const targetWs = userConnections.get(targetUserId);
    if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify(message));
    } else {
        console.log(`Пользователь ${targetUserId} не найден или не в сети`);
    }
}

function forwardMessage(data) {
    const { targetUserId, text, senderId, senderNickname, senderAvatar, isPrivate } = data;
    
    const targetWs = userConnections.get(targetUserId);
    if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({
            type: 'message',
            text: text,
            senderId: senderId,
            senderNickname: senderNickname,
            senderAvatar: senderAvatar,
            isPrivate: !!isPrivate
        }));
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
        const messageStr = JSON.stringify(message);
        room.users.forEach(user => {
            if (user.ws !== excludeWs && user.ws.readyState === WebSocket.OPEN) {
                user.ws.send(messageStr);
            }
        });
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