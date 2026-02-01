const dleService = require('../services/dle');
const storage = require('../services/storage');
const { sendJson } = require('../utils/response');
const crypto = require('crypto');

/**
 * Проверка сессии для Hytale Custom Auth
 */
async function handleSessionCheck(req, res, body) {
    const { uuid, username } = body;

    if (!uuid || !username) {
        return sendJson(res, 400, {
            valid: false,
            error: true,
            message: 'Отсутствуют обязательные поля uuid или username',
            channel: 'ERROR',
            registered: false
        });
    }

    try {
        // Проверяем существование пользователя в системе
        const validation = await dleService.validateUuidAndUsername(uuid, username);

        let valid = false;
        let message = '';
        let registered = validation.registered;
        let channel = validation.channel;

        if (validation.exists) {
            // Пользователь найден в hyt_users
            if (channel === 'FINEMINE') {
                // Для FINEMINE проверяем активную сессию
                const hasActiveSession = await dleService.hasActiveSession(uuid);
                valid = hasActiveSession;
                if (!valid) {
                    message = 'Сессия истекла или не активна';
                }
            } else {
                // Для OTHER/HYTALE достаточно наличия записи
                valid = true;
            }
        } else {
            // Пользователь не найден
            valid = false;
            message = 'Пользователь не зарегистрирован в системе';
            channel = 'HYTALE'; // По умолчанию
        }

        sendJson(res, 200, {
            valid,
            error: !valid,
            message: message,
            channel: channel,
            registered: registered
        });

    } catch (error) {
        console.error('Session check error:', error);
        sendJson(res, 500, {
            valid: false,
            error: true,
            message: 'Внутренняя ошибка сервера',
            channel: 'ERROR',
            registered: false
        });
    }
}

/**
 * Вход для пользователей канала OTHER
 */
async function handleOtherLogin(req, res, body) {
    const { uuid, username, password } = body;

    if (!uuid || !username || !password) {
        return sendJson(res, 400, {
            success: false,
            message: 'Отсутствуют обязательные поля'
        });
    }

    try {
        // Проверяем, существует ли UUID в hyt_users
        const hytUser = await dleService.getHytUserByUuid(uuid);

        if (!hytUser) {
            return sendJson(res, 200, {
                success: false,
                message: 'Пользователь не найден'
            });
        }

        // Проверяем совпадение имени пользователя
        if (hytUser.username !== username) {
            return sendJson(res, 200, {
                success: false,
                message: 'Неверное имя пользователя'
            });
        }

        // Получаем запись из DLE для проверки пароля
        const dleUser = await dleService.getDLEUser(username);

        if (!dleUser) {
            return sendJson(res, 200, {
                success: false,
                message: 'Учетная запись DLE не найдена'
            });
        }

        // Проверяем пароль
        const passwordValid = await dleService.verifyPassword(password, dleUser.password);

        if (!passwordValid) {
            // Обновляем счетчик неудачных попыток
            const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
            await dleService.handleFailedLogin(dleUser, clientIp);

            return sendJson(res, 200, {
                success: false,
                message: 'Неверный пароль'
            });
        }

        // Сбрасываем счетчик неудачных попыток при успешном входе
        await dleService.pool.execute(
            'UPDATE hyt_users SET failed_login_attempts = 0, locked_until = NULL WHERE uuid = ?',
            [uuid]
        );

        sendJson(res, 200, {
            success: true,
            message: 'Успешный вход'
        });

    } catch (error) {
        console.error('Other login error:', error);
        sendJson(res, 500, {
            success: false,
            message: 'Внутренняя ошибка сервера'
        });
    }
}

/**
 * Регистрация для пользователей канала OTHER
 */
async function handleOtherRegister(req, res, body) {
    const { uuid, username, password, email = '' } = body;

    // Валидация
    const usernameError = dleService.validateUsername(username);
    if (usernameError) {
        return sendJson(res, 400, {
            success: false,
            message: usernameError
        });
    }

    if (!password || password.length < 6) {
        return sendJson(res, 400, {
            success: false,
            message: 'Пароль должен быть не менее 6 символов'
        });
    }

    if (email && !validateEmail(email)) {
        return sendJson(res, 400, {
            success: false,
            message: 'Неверный формат email'
        });
    }

    if (!uuid || !isValidUuid(uuid)) {
        return sendJson(res, 400, {
            success: false,
            message: 'Неверный формат UUID'
        });
    }

    try {
        // Проверяем, не занят ли UUID
        const existingByUuid = await dleService.getHytUserByUuid(uuid);
        if (existingByUuid) {
            return sendJson(res, 200, {
                success: false,
                message: 'Пользователь с таким UUID уже существует'
            });
        }

        // Проверяем, не занято ли имя пользователя
        const existingByUsername = await dleService.getHytUserByUsername(username);
        if (existingByUsername) {
            return sendJson(res, 200, {
                success: false,
                message: 'Имя пользователя уже занято'
            });
        }

        // Проверяем, не занято ли имя в DLE
        const existingDleUser = await dleService.getDLEUser(username);
        if (existingDleUser) {
            return sendJson(res, 200, {
                success: false,
                message: 'Имя пользователя уже занято в системе DLE'
            });
        }

        // Создаем пользователя в DLE
        const dleUserId = await dleService.createDleUser(username, password, email, uuid);

        // Создаем запись в hyt_users
        await dleService.createHytUserForOther(dleUserId, username, password, email, uuid, 'OTHER');

        sendJson(res, 200, {
            success: true,
            message: 'Регистрация успешно завершена'
        });

    } catch (error) {
        console.error('Other register error:', error);

        // Проверяем ошибку дублирования уникальных полей
        if (error.code === 'ER_DUP_ENTRY') {
            if (error.sqlMessage.includes('dle_users.name')) {
                return sendJson(res, 200, {
                    success: false,
                    message: 'Имя пользователя уже занято'
                });
            } else if (error.sqlMessage.includes('dle_users.uuid')) {
                return sendJson(res, 200, {
                    success: false,
                    message: 'UUID уже используется'
                });
            }
        }

        sendJson(res, 500, {
            success: false,
            message: 'Ошибка регистрации'
        });
    }
}

/**
 * Вспомогательная функция для валидации email
 */
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

/**
 * Вспомогательная функция для валидации UUID
 */
function isValidUuid(uuid) {
    const re = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return re.test(uuid);
}

module.exports = {
    handleSessionCheck,
    handleOtherLogin,
    handleOtherRegister
};