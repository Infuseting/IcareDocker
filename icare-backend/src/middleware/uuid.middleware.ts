// icare-backend/src/middleware/uuid.middleware.ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { ConfigService } from '@nestjs/config';
import { AppService } from '../app.service';
import { Session } from 'express-session';

@Injectable()
export class UuidMiddleware implements NestMiddleware {
    constructor(private configService: ConfigService, private appService: AppService) {}

    async use(req: Request, res: Response, next: NextFunction) {
        const sessionUUID = req.session['uuid'];
        const queryUUID = req?.query['uuid'];
        const uuid = queryUUID || sessionUUID;
        req.session['uuid'] = uuid;
        if (!uuid) {
            const casLoginUrl = this.configService.get<string>('CAS_LOGIN_URL');
            if (casLoginUrl) {
                return res.redirect('https://' + casLoginUrl);
            }
        }

        const userExists = await this.appService.checkUserExists(req.session['uuid'] as string);
        if (!userExists) {
            const casLoginUrl = this.configService.get<string>('CAS_LOGIN_URL');
            if (casLoginUrl) {
                return res.redirect('https://' + casLoginUrl);
            }
        }

        next();
    }
}

