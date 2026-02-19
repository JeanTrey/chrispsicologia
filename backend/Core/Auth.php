<?php
namespace App\Psico\Core;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use App\Psico\Core\Response;
use App\Psico\Database\Database;
use PDO;

class Auth {
    private static $algorithm = 'HS256';

    /**
     * Retorna a chave secreta do .env
     */
    private static function getSecretKey() {
        $secret = $_ENV['JWT_SECRET'] ?? getenv('JWT_SECRET') ?? '';
        if (empty($secret)) {
            throw new \Exception('FATAL: JWT_SECRET não configurada no arquivo .env');
        }
        return $secret;
    }

    /**
     * Gera um token JWT para o usuário
     */
    public static function generate(int $userId, string $role) {
        $issuedAt = time();
        $expirationTime = $issuedAt + (60 * 60 * 8); // Válido por 8 horas
        
        $payload = [
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            'sub' => $userId,
            'role' => $role
        ];

        return JWT::encode($payload, self::getSecretKey(), self::$algorithm);
    }

    /**
     * Valida um token e retorna o payload decodificado (objeto) ou null se inválido
     */
    public static function validate($token) {
        try {
            return JWT::decode($token, new Key(self::getSecretKey(), self::$algorithm));
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Tenta extrair o token JWT de todas as fontes possíveis (header, body, raw input).
     * Compatível com ambientes serverless como o Vercel.
     */
    public static function resolveToken(): ?string {
        // 1. $_SERVER['HTTP_AUTHORIZATION'] (padrão CGI/FastCGI - Vercel)
        if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
            if (preg_match('/Bearer\s(\S+)/', $_SERVER['HTTP_AUTHORIZATION'], $m)) return $m[1];
        }

        // 2. $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] (quando há rewrite rules)
        if (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            if (preg_match('/Bearer\s(\S+)/', $_SERVER['REDIRECT_HTTP_AUTHORIZATION'], $m)) return $m[1];
        }

        // 3. getallheaders() (Apache mod_php / local)
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
            if (preg_match('/Bearer\s(\S+)/', $authHeader, $m)) return $m[1];
        }

        // 4. $_POST['_token'] — fallback enviado explicitamente pelo JS
        if (!empty($_POST['_token'])) {
            return $_POST['_token'];
        }

        // 5. Corpo bruto da requisição (caso $_POST não seja preenchido pelo PHP serverless)
        $rawBody = file_get_contents('php://input');
        if (!empty($rawBody)) {
            parse_str($rawBody, $parsedBody);
            if (!empty($parsedBody['_token'])) {
                return $parsedBody['_token'];
            }
        }

        return null;
    }

    /**
     * Middleware: Verifica o token e para a execução se inválido.
     */
    public static function check() {
        $token = self::resolveToken();

        if (!$token) {
            Response::error('Token não fornecido ou inválido.', 401);
            exit;
        }

        // 1. Tenta validar como Token Fixo (API_TOKEN do .env - para Desktop App)
        $apiToken = $_ENV['API_TOKEN'] ?? getenv('API_TOKEN') ?? '';
        if (!empty($apiToken) && $token === $apiToken) {
            return (object) [
                'sub'  => 0,
                'role' => 'admin',
                'iat'  => time(),
                'exp'  => time() + 3600
            ];
        }

        // 2. Tenta validar como JWT
        $payload = self::validate($token);

        if (!$payload) {
            Response::error('Token expirado ou inválido.', 401);
            exit;
        }

        return $payload;
    }

    /**
     * Gera um Refresh Token (aleatório, opaco), salva no banco (hash) e retorna o token puro.
     * Validade: 30 dias.
     */
    public static function generateRefreshToken(int $userId) {
        $token = bin2hex(random_bytes(32)); // 64 chars
        $hash = hash('sha256', $token);
        
        $expiresAt = date('Y-m-d H:i:s', time() + (60 * 60 * 24 * 30)); // 30 dias

        $db = Database::getInstance();
        $stmt = $db->prepare("INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)");
        $stmt->execute([$userId, $hash, $expiresAt]);

        return $token;
    }

    /**
     * Verifica se o refresh token é válido e retorna o user_id.
     * Retorna false se inválido ou expirado.
     */
    public static function verifyRefreshToken($token) {
        $hash = hash('sha256', $token);
        $db = Database::getInstance();
        
        $stmt = $db->prepare("SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = ?");
        $stmt->execute([$hash]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) return false;

        if (strtotime($row['expires_at']) < time()) {
            self::revokeRefreshToken($token);
            return false;
        }

        return (int)$row['user_id'];
    }

    /**
     * Remove o refresh token do banco.
     */
    public static function revokeRefreshToken($token) {
        $hash = hash('sha256', $token);
        $db = Database::getInstance();
        $stmt = $db->prepare("DELETE FROM refresh_tokens WHERE token_hash = ?");
        $stmt->execute([$hash]);
    }
}
