const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const config = require('../config');

// Регулярное выражение для имени пользователя (совпадает с PHP)
const USERNAME_REGEX = /^[a-zA-Zа-яА-Я0-9_]+$/u;

class DLEService {
    constructor() {
        this.pool = mysql.createPool({
            host: config.dleDb.host,
            port: config.dleDb.port,
            user: config.dleDb.user,
            password: config.dleDb.password,
            database: config.dleDb.database,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            charset: 'utf8mb4'
        });
    }

    /**
     * Проверяет имя пользователя на соответствие требованиям
     */
    validateUsername(username) {
        if (!username || username.length < config.minUsernameLength) {
            return `Имя пользователя должно быть не короче ${config.minUsernameLength} символов`;
        }

        if (!USERNAME_REGEX.test(username)) {
            return 'Имя пользователя может содержать только буквы (в т.ч. русские), цифры и подчёркивание';
        }

        return null;
    }

    /**
     * Получает пользователя DLE по имени
     */
    async getDLEUser(username) {
        try {
            const [rows] = await this.pool.execute(
                'SELECT user_id, name, email, password FROM dle_users WHERE name = ? LIMIT 1',
                [username]
            );
            return rows[0] || null;
        } catch (error) {
            console.error('Error getting DLE user:', error);
            return null;
        }
    }

    /**
     * Проверяет пароль DLE (BCrypt с префиксом $2y$)
     */
    async verifyPassword(password, hash) {
        try {
            // Преобразуем префикс $2y$ в $2b$ для совместимости с bcryptjs
            if (hash.startsWith('$2y$')) {
                hash = '$2b$' + hash.slice(4);
            }

            return await bcrypt.compare(password, hash);
        } catch (error) {
            console.error('Error verifying password:', error);
            return false;
        }
    }

    /**
     * Получает или создает запись в hyt_users
     */
    async getOrCreateHytUser(dleUser, clientIp = '0.0.0.0', channel = 'FINEMINE') {
        try {
            // Проверяем существующую запись
            const [existing] = await this.pool.execute(
                'SELECT user_id, uuid, channel, failed_login_attempts, locked_until FROM hyt_users WHERE dle_user_id = ? LIMIT 1',
                [dleUser.user_id]
            );

            const now = new Date().toISOString().slice(0, 19).replace('T', ' ');

            if (existing.length > 0) {
                const user = existing[0];

                // Проверяем блокировку
                if (user.locked_until && new Date(user.locked_until) > new Date()) {
                    throw new Error('Аккаунт заблокирован. Попробуйте позже.');
                }

                // Обновляем последний вход
                await this.pool.execute(
                    'UPDATE hyt_users SET last_login_at = ?, login_ip = ?, failed_login_attempts = 0, locked_until = NULL WHERE user_id = ?',
                    [now, clientIp, user.user_id]
                );

                return {
                    user_id: user.user_id,
                    uuid: user.uuid,
                    channel: user.channel || channel
                };
            } else {
                // Создаем новую запись
                const uuid = crypto.randomUUID();

                await this.pool.execute(
                    `INSERT INTO hyt_users 
           (dle_user_id, username, email, password, uuid, channel, created_at, last_login_at, login_ip, failed_login_attempts, locked_until)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)`,
                    [
                        dleUser.user_id,
                        dleUser.name,
                        dleUser.email,
                        dleUser.password,
                        uuid,
                        channel,
                        now,
                        now,
                        clientIp
                    ]
                );

                return {
                    user_id: dleUser.user_id,
                    uuid,
                    channel
                };
            }
        } catch (error) {
            console.error('Error in getOrCreateHytUser:', error);
            throw error;
        }
    }

    /**
     * Обрабатывает неудачную попытку входа
     */
    async handleFailedLogin(dleUser, clientIp) {
        try {
            const [existing] = await this.pool.execute(
                'SELECT user_id, failed_login_attempts FROM hyt_users WHERE dle_user_id = ? LIMIT 1',
                [dleUser.user_id]
            );

            const now = new Date().toISOString().slice(0, 19).replace('T', ' ');

            if (existing.length > 0) {
                const user = existing[0];
                const newAttempts = user.failed_login_attempts + 1;
                let lockedUntil = null;

                if (newAttempts >= config.maxFailedAttempts) {
                    const lockDate = new Date();
                    lockDate.setMinutes(lockDate.getMinutes() + config.lockTimeMinutes);
                    lockedUntil = lockDate.toISOString().slice(0, 19).replace('T', ' ');
                }

                await this.pool.execute(
                    'UPDATE hyt_users SET failed_login_attempts = ?, locked_until = ?, last_login_at = ?, login_ip = ? WHERE user_id = ?',
                    [newAttempts, lockedUntil, now, clientIp, user.user_id]
                );
            } else {
                // Создаем запись с неудачной попыткой
                const uuid = crypto.randomUUID();
                await this.pool.execute(
                    `INSERT INTO hyt_users 
           (dle_user_id, username, email, password, uuid, channel, created_at, last_login_at, login_ip, failed_login_attempts, locked_until)
           VALUES (?, ?, ?, ?, ?, 'FINEMINE', ?, ?, ?, 1, NULL)`,
                    [
                        dleUser.user_id,
                        dleUser.name,
                        dleUser.email,
                        dleUser.password,
                        uuid,
                        now,
                        now,
                        clientIp
                    ]
                );
            }
        } catch (error) {
            console.error('Error handling failed login:', error);
        }
    }

    /**
     * Получает UUID пользователя из hyt_users
     */
    async getUserUuid(dleUserId) {
        try {
            const [rows] = await this.pool.execute(
                'SELECT uuid FROM hyt_users WHERE dle_user_id = ? LIMIT 1',
                [dleUserId]
            );
            return rows[0]?.uuid || null;
        } catch (error) {
            console.error('Error getting user UUID:', error);
            return null;
        }
    }
}

module.exports = new DLEService();