import jwt from 'jsonwebtoken';

if(!process.env.JWTSECRET) throw new Error("no jwt secret")

export type JWTPayload = {
    id: string,
    twofaAuthorized?: string
}
export class JWTUtils {
    private static readonly ACCESS_TOKEN_EXPIRES_IN: string = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
    private static readonly REFRESH_TOKEN_EXPRIRES_IN: string = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';
    private static readonly JWT_SECRET: string = process.env.JWTSECRET!;

    private static getSecret(): string {
        return this.JWT_SECRET;
    }
    static getRefreshToken(payload: JWTPayload): string {
        const options = {
            algorithm: 'HS256',
            expiresIn: this.REFRESH_TOKEN_EXPRIRES_IN
        };
        const secret = this.getSecret();

        return jwt.sign(payload, secret, options)
    }
    static getAccessToken(payload): string {
        const options = {
            algorithm: 'HS256',
            expiresIn: this.ACCESS_TOKEN_EXPIRES_IN
        };
        const secret = this.getSecret();

        return jwt.sign(payload, secret, options)
    }
    static getTokenPair(payload: JWTPayload): {
        accessToken: string,
        refreshToken: string
    } {
        const tokenPair = {
            accessToken: this.getAccessToken(payload),
            refreshToken: this.getRefreshToken(payload)
        }

        return tokenPair
    }
    static verifyToken(token: string): JWTPayload {
        const secret = this.getSecret();
        const result: JWTPayload = jwt.verify(token, secret);
        
        if (typeof result == 'string') throw new Error('jwt payload is a string (must be an object');
       
        return result;
    }
}