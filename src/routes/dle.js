const dleService = require('../services/dle');
const auth = require('../services/auth');
const storage = require('../services/storage');
const { sendJson } = require('../utils/response');
const crypto = require('crypto');
const config = require('../config');

/**
 * DLE аутентификация - проверка логина и пароля
 */
async function handleDleAuth(req, res, body) {
    const { username, password } = body;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';

    // Валидация входных данных
    const usernameError = dleService.validateUsername(username);
    if (usernameError) {
        return sendJson(res, 400, {
            success: false,
            error: usernameError
        });
    }

    if (!password) {
        return sendJson(res, 400, {
            success: false,
            error: 'Пароль не может быть пустым'
        });
    }

    try {
        // Получаем пользователя DLE
        const dleUser = await dleService.getDLEUser(username);
        if (!dleUser) {
            return sendJson(res, 401, {
                success: false,
                error: 'Неверный логин или пароль'
            });
        }

        // Проверяем пароль
        const passwordValid = await dleService.verifyPassword(password, dleUser.password);
        if (!passwordValid) {
            // Обрабатываем неудачную попытку
            await dleService.handleFailedLogin(dleUser, clientIp);
            return sendJson(res, 401, {
                success: false,
                error: 'Неверный логин или пароль'
            });
        }

        // Получаем или создаем запись в hyt_users
        const hytUser = await dleService.getOrCreateHytUser(dleUser, clientIp, 'FINEMINE');

        // Генерируем токены (используем существующую логику)
        const requestHost = req.headers.host;
        const identityToken = auth.generateIdentityToken(hytUser.uuid, username, null, ['game.base'], requestHost);
        const sessionToken = auth.generateSessionToken(hytUser.uuid, requestHost);

        // Регистрируем сессию в Redis
        await storage.registerSession(sessionToken, hytUser.uuid, username, null);

        // Синхронизируем имя пользователя в Redis
        await storage.persistUsername(hytUser.uuid, username);

        // Генерируем profile_id (аналогично PHP)
        const profileId = crypto.randomBytes(16).toString('hex');
        const expiresAt = new Date(Date.now() + config.sessionTtl * 1000).toISOString();

        // Возвращаем ответ в формате, совместимом с текущей системой
        sendJson(res, 200, {
            success: true,
            uuid: hytUser.uuid,
            identityToken: identityToken,
            sessionToken: sessionToken,
            expiresIn: config.sessionTtl,
            expiresAt: expiresAt,
            tokenType: 'Bearer',
            // Дополнительные поля из DLE
            profile_id: profileId,
            channel: hytUser.channel || 'FINEMINE',
            auth_mode: 'authenticated', // или 'offline' если нужно
            user: {
                uuid: hytUser.uuid,
                name: username,
                premium: true
            }
        });

    } catch (error) {
        console.error('DLE auth error:', error);

        if (error.message === 'Аккаунт заблокирован. Попробуйте позже.') {
            return sendJson(res, 403, {
                success: false,
                error: error.message
            });
        }

        sendJson(res, 500, {
            success: false,
            error: 'Внутренняя ошибка сервера'
        });
    }
}

/**
 * Проверка существования пользователя DLE (для регистрации)
 */
async function handleDleCheck(req, res, body) {
    const { username } = body;

    const usernameError = dleService.validateUsername(username);
    if (usernameError) {
        return sendJson(res, 400, {
            exists: false,
            error: usernameError
        });
    }

    try {
        const user = await dleService.getDLEUser(username);
        sendJson(res, 200, {
            exists: !!user,
            username: username
        });
    } catch (error) {
        console.error('DLE check error:', error);
        sendJson(res, 200, {
            exists: false,
            username: username
        });
    }
}

module.exports = {
    handleDleAuth,
    handleDleCheck
};