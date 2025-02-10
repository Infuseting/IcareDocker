import { Controller, Get, Post, Body, Res, Req } from '@nestjs/common';
import { Response, Request } from 'express';
import { AppService, ICal } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}
    @Get('/api/statut')
    getStatut() {
      return "API ONLINE"
    }


    @Post('/api/user/permission/edit')
    async updateUserPermission(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
      if (!await this.appService.hasAdminPermission(req.session['uuid'], 2)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to modify permissions of user' });
        }

        const { USE_UUID, permissions } = body;

        if (!USE_UUID) {
            return res.status(400).json({ status: 'error', message: 'UUID of User is required' });
        }

        if (permissions && Array.isArray(permissions)) {
            const deleteSQL = "DELETE FROM ICA_USER_HAS_PERMISSION WHERE USE_UUID = ?";
            await this.appService.executeSql(deleteSQL, [USE_UUID]);

            for (const permission of permissions[0].split(',')) {
                if (permission.length === 0) {
                    continue;
                }

                const insertSQL = "INSERT INTO ICA_USER_HAS_PERMISSION (USE_UUID, PER_ID) VALUES (?, ?)";
                await this.appService.executeSql(insertSQL, [USE_UUID, permission]);
            }

            return res.json({ status: 'success', message: 'User permission modified' });
        } else {
            return res.json({ status: 'success', message: 'No permission modified' });
        }
    }
    @Post('/api/user/role/edit')
    async updateUserRole(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 2)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to modify roles of user' });
        }

        const { USE_UUID, roles } = body;

        if (!USE_UUID) {
            return res.status(400).json({ status: 'error', message: 'UUID of User is required' });
        }

        if (roles && Array.isArray(roles)) {
            const deleteSQL = "DELETE FROM ICA_USER_HAS_ROLE WHERE USE_UUID = ?";
            await this.appService.executeSql(deleteSQL, [USE_UUID]);

            for (const role of roles[0].split(',')) {
                if (role.length === 0) {
                    continue;
                }

                const insertSQL = "INSERT INTO ICA_USER_HAS_ROLE (USE_UUID, ROL_ID) VALUES (?, ?)";
                await this.appService.executeSql(insertSQL, [USE_UUID, role]);
            }

            return res.json({ status: 'success', message: 'User role modified' });
        } else {
            return res.json({ status: 'success', message: 'Roles modification is not set' });
        }
    }
    @Get('/api/user/get')
    async getUser(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 2) && !await this.appService.hasAdminPermission(req.session['uuid'], 6) && !await this.appService.hasAdminPermission(req.session['uuid'], 11)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to view users' });
        }
        const deleteSQL = "SELECT * FROM ICA_User";
        const permission = await this.appService.executeSql(deleteSQL, []);
        return res.json({ status: 'success', data: permission });
    }


    @Get('/api/role/get')
    async getRole(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 2) && !await this.appService.hasAdminPermission(req.session['uuid'], 3)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to view users' });
        }
        const deleteSQL = "SELECT * FROM ICA_Role";
        const permission = await this.appService.executeSql(deleteSQL, []);
        return res.json({ status: 'success', data: permission });

    }
    @Post('/api/role/create')
    async createRole(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 4)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to create a new role' });
        }
        const { name, permissions } = body;
        if (!name) {
            return res.status(400).json({ status: 'error', message: 'Role name is required' });
        }
        const insertRoleSQL = "INSERT INTO ICA_Role (ROL_Libelle) VALUES (?)";
        const result = await this.appService.executeSql(insertRoleSQL, [name]);
        const roleId = result.insertId;

        if (permissions && Array.isArray(permissions)) {
            if (!await this.appService.hasAdminPermission(req.session['uuid'], 3)) {
                return res.status(403).json({ status: 'error', message: 'You do not have permissions to add permissions' });
            }
            for (const permission of permissions) {
                if (permission.length === 0) {
                    continue;
                }
                const insertPermissionSQL = "INSERT INTO ICA_ROLE_HAS_PERMISSION (ROL_ID, PER_ID) VALUES (?, ?)";
                await this.appService.executeSql(insertPermissionSQL, [roleId, permission]);
            }
            return res.json({ status: 'success', message: 'Role created with permissions' });
        } else {
            return res.json({ status: 'success', message: 'Role created without any permissions' });
        }
    }
    @Post('/api/role/delete')
    async deleteRole(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 5)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to delete a role' });
        }

        const { ROL_ID } = body;

        if (!ROL_ID) {
            return res.status(400).json({ status: 'error', message: 'Role ID is required' });
        }

        try {
            const deleteRolePermissionSQL = "DELETE FROM ICA_ROLE_HAS_PERMISSION WHERE ROL_ID = ?";
            await this.appService.executeSql(deleteRolePermissionSQL, [ROL_ID]);

            const deleteUserRoleSQL = "DELETE FROM ICA_USER_HAS_ROLE WHERE ROL_ID = ?";
            await this.appService.executeSql(deleteUserRoleSQL, [ROL_ID]);

            const deleteRoleSQL = "DELETE FROM ICA_Role WHERE ROL_ID = ?";
            await this.appService.executeSql(deleteRoleSQL, [ROL_ID]);

            return res.json({ status: 'success', message: 'Role deleted successfully' });
        } catch (error) {
            return res.status(500).json({ status: 'error', message: 'Error while deleting role' });
        }
    }
    @Post('/api/role/edit')
    async updateRole(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 3)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to modify a role' });
        }

        const { ROL_ID, name, permissions } = body;

        if (!ROL_ID) {
            return res.status(400).json({ status: 'error', message: 'Role ID is required' });
        }
        if (permissions && Array.isArray(permissions)) {
            if (!await this.appService.hasAdminPermission(req.session['uuid'], 3)) {
                return res.status(403).json({ status: 'error', message: 'You do not have permissions to modify permissions' });
            }

            const deletePermissionsSQL = "DELETE FROM ICA_ROLE_HAS_PERMISSION WHERE ROL_ID = ?";
            await this.appService.executeSql(deletePermissionsSQL, [ROL_ID]);

            for (const permission of permissions[0].split(',')) {
                if (permission.length === 0) {
                    continue;
                }

                const insertPermissionSQL = "INSERT INTO ICA_ROLE_HAS_PERMISSION (ROL_ID, PER_ID) VALUES (?, ?)";
                await this.appService.executeSql(insertPermissionSQL, [ROL_ID, permission]);
            }

            return res.json({ status: 'success', message: 'Role modified with permissions' });
        } else {
            return res.json({ status: 'success', message: 'Role modified without any permissions' });
        }
    }

    @Get('/api/permission/get')
    async getPermission(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 2) && !await this.appService.hasAdminPermission(req.session['uuid'], 3)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to view users' });
        }
        const deleteSQL = "SELECT * FROM ICA_Permission";
        const permission = await this.appService.executeSql(deleteSQL, []);
        return res.json({ status: 'success', data: permission });

    }


    @Post('/api/edt/add')
    async addEdt(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        const { USE_UUID, EDT_LINK, EDT_COLOR, EDT_LIBELLE } = body;

        if (!USE_UUID || !EDT_LINK || !EDT_COLOR || !EDT_LIBELLE) {
            return res.status(400).json({ status: 'error', message: 'USE_UUID, EDT_LINK, EDT_COLOR, and EDT_LIBELLE are required' });
        }

        if (!await this.appService.hasAdminPermission(req.session['uuid'], 13) && USE_UUID != req.session['uuid']) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to add EDT' });
        }



        try {
            const insertEdtSQL = "INSERT INTO ICA_EDT (EDT_LINK, EDT_Color, EDT_NAME) VALUES (?, ?, ?)";
            const result = await this.appService.executeSql(insertEdtSQL, [EDT_LINK, EDT_COLOR, EDT_LIBELLE]);
            const insertId = result.insertId;

            const insertAppartientSQL = "INSERT INTO ICA_APPARTIENT (USE_UUID, EDT_ID) VALUES (?, ?)";
            await this.appService.executeSql(insertAppartientSQL, [USE_UUID, insertId]);

            return res.json({ status: 'success', message: 'EDT added successfully' });
        } catch (error) {
            return res.status(500).json({ status: 'error', message: 'Failed to add EDT' });
        }
    }
    @Post('/api/edt/delete')
    async deleteEdt(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        const { USE_UUID, EDT_ID } = body;

        if (!USE_UUID || !EDT_ID) {
            return res.status(400).json({ status: 'error', message: 'USE_UUID and EDT_ID are required' });
        }

        if (!await this.appService.hasAdminPermission(req.session['uuid'], 13) && USE_UUID != req.session['uuid']) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to add EDT' });
        }



        try {
            const deleteAppartientSQL = "DELETE FROM ICA_APPARTIENT WHERE USE_UUID = ? AND EDT_ID = ?";
            await this.appService.executeSql(deleteAppartientSQL, [USE_UUID, EDT_ID]);

            const deleteEdtSQL = "DELETE FROM ICA_EDT WHERE EDT_ID = ?";
            await this.appService.executeSql(deleteEdtSQL, [EDT_ID]);

            return res.json({ status: 'success', message: 'EDT removed successfully' });
        } catch (error) {
            return res.status(500).json({ status: 'error', message: 'Failed to delete EDT' });
        }
    }


    @Get('/api/calendar/get')
    async getCalendar(@Req() req: Request & { session: any }, @Res() res: Response) {
        const uuid = req.query.id as string;

        const userEventsSQL = `
        SELECT * FROM ICA_User 
        JOIN ICA_APPARTIENT USING (USE_UUID) 
        JOIN ICA_EDT USING (EDT_ID) 
        WHERE USE_UUID = ?
    `;
        const userEvents = await this.appService.executeSql(userEventsSQL, [uuid]);
        let events: { DTSTART: string; DTEND: string; SUMMARY: string; LOCATION: string }[] = [];
        for (const row of userEvents) {
            const url = row.EDT_Link;
            const parsedEvents: { DTSTART: string; DTEND: string; SUMMARY: string; LOCATION: string }[] = await this.parseICS(url);
            events = events.concat(parsedEvents);
        }

        const calendarEventsSQL = `
            SELECT * FROM ICA_User
                              JOIN ICA_Calendar USING (USE_UUID)
            WHERE USE_UUID = ?
        `;
        const calendarEvents = await this.appService.executeSql(calendarEventsSQL, [uuid]);

        for (const row of calendarEvents) {
            const event: { DTSTART: string; DTEND: string; SUMMARY: string; LOCATION: string } = {
                DTSTART: row.CAL_HORAIRE_DEBUT,
                DTEND: row.CAL_HORAIRE_FIN,
                SUMMARY: row.CAL_Libelle,
                LOCATION: ''
            };
            events.push(event);
        }
        const icsData = this.generateICS(events);
        res.json({ status: 'success', data: icsData });
    }
    private async parseICS(icsUrl: string): Promise<any[]> {
        const ical = await new ICal(icsUrl);
        ical.sortEventsWithOrder(await ical.events());
        return ical.events();
    }
    private generateICS(events: any[]): string {
        let ics = "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Icare Organizations//NONSGML v1.0//EN\n";
        for (const event of events) {
            //console.log(event);
            ics += "BEGIN:VEVENT\n";
            for (const key in event) {
                ics += `${key}:${event[key]}\n`;
            }
            ics += "END:VEVENT\n";
        }
        ics += "END:VCALENDAR";
        return ics;
    }
    @Post('/api/calendar/delete')
    async deleteCalendar(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 13) && req.session['uuid'] !== body.USE_UUID) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to modify permissions' });
        }
        if (body.USE_UUID && body.CAL_ID) {
            const deleteCalendarSQL = "DELETE FROM ICA_Calendar WHERE USE_UUID = ? AND CAL_ID = ?";
            await this.appService.executeSql(deleteCalendarSQL, [body.USE_UUID, body.CAL_ID]);
            return res.json({ status: 'success', message: 'Calendar event removed successfully' });
        } else {
            return res.status(400).json({ status: 'error', message: 'USE_UUID and CAL_ID are required' });
        }
    }
    @Post('/api/calendar/save')
    async saveCalendar(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 13) && req.session['uuid'] !== body.USE_UUID) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to modify permissions' });
        }
        if (body.CAL_ID && body.USE_UUID && body.CAL_Libelle && body.CAL_HORAIRE_DEBUT && body.CAL_HORAIRE_FIN) {
            const dateDebut = new Date(body.CAL_HORAIRE_DEBUT);
            const dateFin = new Date(body.CAL_HORAIRE_FIN);
            const calHoraireDebut = dateDebut.toISOString().replace('T', ' ').substring(0, 19);
            const calHoraireFin = dateFin.toISOString().replace('T', ' ').substring(0, 19);
            const insertCalendarSQL = "INSERT INTO ICA_Calendar (USE_UUID, CAL_Libelle, CAL_HORAIRE_DEBUT, CAL_HORAIRE_FIN) VALUES (?, ?, ?, ?)";
            await this.appService.executeSql(insertCalendarSQL, [body.USE_UUID, body.CAL_Libelle, calHoraireDebut, calHoraireFin]);
            return res.json({ status: 'success', message: 'Calendar event created successfully' });
        } else {
            return res.status(400).json({ status: 'error', message: 'Role name, start time, and end time are required' });
        }
    }


    @Get('/api/class/get')
    async getClass(@Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 8)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to manage class' });
        }
        const deleteSQL = "SELECT * FROM ICA_Classe";
        const permission = await this.appService.executeSql(deleteSQL, []);
        return res.json({ status: 'success', data: permission });
    }
    @Post('/api/class/add')
    async addClass(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 8)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to manage class' });
        }
        const { ETU_ID, NIV_ID, TYPC_ID, CLA_Libelle, heritage } = body;
        if (!ETU_ID) {
            return res.status(400).json({ status: 'error', message: 'etu id is required' });
        }
        if (!NIV_ID) {
            return res.status(400).json({ status: 'error', message: 'Niveau id is required' });
        }
        if (!TYPC_ID) {
            return res.status(400).json({ status: 'error', message: 'Type class id is required' });
        }
        if (!CLA_Libelle) {
            return res.status(400).json({ status: 'error', message: 'Class name is required' });
        }
        try {
            const insertClassSQL = 'INSERT INTO ICA_Classe (ETU_ID, NIV_ID, TYPC_ID, CLA_Libelle) VALUES (?, ?, ?, ?)';
            const result = await this.appService.executeSql(insertClassSQL, [ETU_ID, NIV_ID, TYPC_ID, CLA_Libelle]);
            const classeId = result.insertId;
            if (heritage && Array.isArray(heritage)) {
                for (const ancetre of heritage[0].split(',')) {
                    if (ancetre.length === 0) {
                        continue;
                    }
                    const insertHeritageSQL = 'INSERT INTO ICA_HERITE(CLA_ID, ANCETRE_CLA_ID) VALUES (?, ?)';
                    await this.appService.executeSql(insertHeritageSQL, [classeId, ancetre]);
                }
                return res.json({ status: 'success', message: 'Class added successfully with heritage' });
            } else {
                return res.json({ status: 'success', message: 'Class added successfully' });
            }
        } catch (error) {
            return res.status(500).json({ status: 'error', message: 'Failed to add class' });
        }
    }
    @Post('/api/class/edit')
    async editClass(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 8)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to manage class' });
        }
        const { CLA_ID, heritage } = body;
        if (!CLA_ID) {
            return res.status(400).json({ status: 'error', message: 'Class ID is required' });
        }
        if (heritage && Array.isArray(heritage)) {
            const deleteHeritageSQL = "DELETE FROM ICA_HERITE WHERE CLA_ID = ?";
            await this.appService.executeSql(deleteHeritageSQL, [CLA_ID]);
            for (const ancetre of heritage[0].split(',')) {
                if (ancetre.length === 0) {
                    continue;
                }
                const insertHeritageSQL = "INSERT INTO ICA_HERITE(CLA_ID, ANCETRE_CLA_ID) VALUES (?, ?)";
                await this.appService.executeSql(insertHeritageSQL, [CLA_ID, ancetre]);
            }
            return res.json({ status: 'success', message: 'Class edited successfully with heritage' });
        } else {
            return res.status(400).json({ status: 'error', message: 'Heritage is required' });
        }
    }
    @Post('/api/class/delete')
    async deleteClass(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 8)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to manage class' });
        }
        if (body.CLA_ID) {
            const deleteHeritageSQL = 'DELETE FROM ICA_HERITE WHERE ANCETRE_CLA_ID = ?';
            await this.appService.executeSql(deleteHeritageSQL, [body.CLA_ID]);
            const deleteClassSQL = 'DELETE FROM ICA_Classe WHERE CLA_ID = ?';
            await this.appService.executeSql(deleteClassSQL, [body.CLA_ID]);
            return res.json({ status: 'success', message: 'Class removed successfully' });
        } else {
            return res.status(400).json({ status: 'error', message: 'Class ID is required' });
        }
    }


    @Get('/api/distance/get')
    async getDistance(@Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 10)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permission to get distance between two batiments' });
        }
        const deleteSQL = 'SELECT * FROM ICA_Distance';
        const permission = await this.appService.executeSql(deleteSQL, []);
        return res.json({ status: 'success', data: permission });
    }
    @Post('/api/distance/edit')
    async editDistance(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 10)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to manage class' });
        }
        const { BAT_ID1, BAT_ID2, DIS_Temps } = body;
        if (!BAT_ID1) {
            return res.status(400).json({ status: 'error', message: 'bat id 1 is required' });
        }
        if (!BAT_ID2) {
            return res.status(400).json({ status: 'error', message: 'type is required' });
        }
        if (DIS_Temps === undefined) {
            return res.status(400).json({ status: 'error', message: 'temps is required' });
        }
        if (DIS_Temps < 0 || DIS_Temps > 300) {
            return res.status(400).json({ status: 'error', message: 'temps must be between 0 and 300' });
        }

        const selectSQL = 'SELECT * FROM ICA_Distance WHERE BAT_ID1 = ? AND BAT_ID2 = ?';
        const result = await this.appService.executeSql(selectSQL, [BAT_ID1, BAT_ID2]);
        if (result.length > 0) {
            const updateSQL = 'UPDATE ICA_Distance SET DIS_Temps = ? WHERE BAT_ID1 = ? AND BAT_ID2 = ?';
            await this.appService.executeSql(updateSQL, [DIS_Temps, BAT_ID1, BAT_ID2]);
            await this.appService.executeSql(updateSQL, [DIS_Temps, BAT_ID2, BAT_ID1]);
            return res.json({ status: 'success', message: 'updated successfully' });
        } else {
            const insertSQL = 'INSERT INTO ICA_Distance(BAT_ID1, BAT_ID2, DIS_Temps) VALUES (?, ?, ?)';
            await this.appService.executeSql(insertSQL, [BAT_ID1, BAT_ID2, DIS_Temps]);
            await this.appService.executeSql(insertSQL, [BAT_ID2, BAT_ID1, DIS_Temps]);
            return res.json({ status: 'success', message: 'added successfully' });
        }
    }

    @Get('/api/format/get')
    async getFormat(@Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 7)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permission to get distance between two batiments' });
        }
        const deleteSQL = 'SELECT * FROM ICA_FORMAT';
        const permission = await this.appService.executeSql(deleteSQL, []);
        return res.json({ status: 'success', data: permission });
    }
    @Get('/api/format/cours/get')
    async getCours(@Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 7)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permission to get distance between two batiments' });
        }
        const deleteSQL = 'SELECT * FROM ICA_Distance';
        const permission = await this.appService.executeSql(deleteSQL, []);
        return res.json({ status: 'success', data: permission });
    }
    @Post('/api/format/cours/add')
    async addCours(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 7)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to create a new matieres' });
        }
        const { MAT_ID, SEM_ID, ETU_ID } = body;
        if (!MAT_ID) {
            return res.status(400).json({ status: 'error', message: 'MAT_ID is required' });
        }
        if (!SEM_ID) {
            return res.status(400).json({ status: 'error', message: 'SEM_ID is required' });
        }
        if (!ETU_ID) {
            return res.status(400).json({ status: 'error', message: 'ETU_ID is required' });
        }
        const SQL = "INSERT INTO ICA_FORMAT (MAT_ID, SEM_ID, ETU_ID) VALUES (?, ?, ?)";
        await this.appService.executeSql(SQL, [MAT_ID, SEM_ID, ETU_ID]);
        return res.json({ status: 'success', message: 'Cours added' });
    }
    @Post('/api/format/cours/delete')
    async deleteCours(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 7)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to delete a matieres' });
        }
        const { MAT_ID, SEM_ID, ETU_ID } = body;
        if (!MAT_ID) {
            return res.status(400).json({ status: 'error', message: 'MAT_ID is required' });
        }
        if (!SEM_ID) {
            return res.status(400).json({ status: 'error', message: 'SEM_ID is required' });
        }
        if (!ETU_ID) {
            return res.status(400).json({ status: 'error', message: 'ETU_ID is required' });
        }
        const SQL = "DELETE FROM ICA_FORMAT WHERE MAT_ID = ? AND SEM_ID = ? AND ETU_ID = ?";
        await this.appService.executeSql(SQL, [MAT_ID, SEM_ID, ETU_ID]);
        return res.json({ status: 'success', message: 'Cours deleted' });
    }

    @Get('/api/format/matiere/get')
    async getMatiere(@Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 7)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permission to get matieres' });
        }
        const deleteSQL = 'SELECT * FROM ICA_Matiere';
        const permission = await this.appService.executeSql(deleteSQL, []);
        return res.json({ status: 'success', data: permission });
    }
    @Post('/api/format/matiere/add')
    async addMatiere(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 7)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to create a new matieres' });
        }
        const { MAT_Libelle } = body;
        if (MAT_Libelle) {
            const SQL = "INSERT INTO ICA_Matiere (MAT_Libelle) VALUES (?)";
            await this.appService.executeSql(SQL, [MAT_Libelle]);
            return res.json({ status: 'success', message: 'Matiere created' });
        } else {
            return res.status(400).json({ status: 'error', message: 'MAT_Libelle is required' });
        }
    }

    @Get('/api/format/study/get')
    async getStudy(@Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 7)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permission to get matieres' });
        }
        const deleteSQL = 'SELECT * FROM ICA_Etude';
        const permission = await this.appService.executeSql(deleteSQL, []);
        return res.json({ status: 'success', data: permission });
    }
    @Post('/api/format/study/add')
    async addStudy(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 7)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to create a new study' });
        }
        if (body.ETU_Libelle) {
            const SQL = "INSERT INTO ICA_Etude (ETU_Libelle) VALUES (?)";
            await this.appService.executeSql(SQL, [body.ETU_Libelle]);
            return res.json({ status: 'success', message: 'Study created' });
        } else {
            return res.status(400).json({ status: 'error', message: 'ETU_Libelle is required' });
        }
    }


    @Post('/api/prof/add')
    async addProf(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 6)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to manage prof' });
        }
        const { USE_UUID, STA_ID, matieres } = body;
        if (!USE_UUID) {
            return res.status(400).json({ status: 'error', message: 'User id is required' });
        }
        if (!STA_ID) {
            return res.status(400).json({ status: 'error', message: 'Status id is required' });
        }
        if (!matieres || !Array.isArray(matieres)) {
            return res.status(400).json({ status: 'error', message: 'Matiere id is required' });
        }

        const SQL = "INSERT INTO ICA_Prof (USE_UUID, STA_ID) VALUES (?, ?)";
        await this.appService.executeSql(SQL, [USE_UUID, STA_ID]);

        for (const matiere of matieres[0].split(',')) {
            if (matiere.length === 0) {
                continue;
            }
            const SQL3 = "INSERT INTO ICA_Responsable (USE_UUID, MAT_ID) VALUES (?, ?)";
            await this.appService.executeSql(SQL3, [USE_UUID, matiere]);
        }

        return res.json({ status: 'success', message: 'Prof created successfully' });
    }
    @Post('/api/prof/delete')
    async deleteProf(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 6)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to manage prof' });
        }
        if (body.USE_UUID) {
            const deleteResponsableSQL = "DELETE FROM ICA_Responsable WHERE USE_UUID = ?";
            await this.appService.executeSql(deleteResponsableSQL, [body.USE_UUID]);

            const deleteProfSQL = "DELETE FROM ICA_Prof WHERE USE_UUID = ?";
            await this.appService.executeSql(deleteProfSQL, [body.USE_UUID]);

            return res.json({ status: 'success', message: 'Prof deleted successfully' });
        } else {
            return res.status(400).json({ status: 'error', message: 'User id is required' });
        }
    }
    @Post('/api/prof/edit')
    async editProf(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 6)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to manage prof' });
        }
        const { USE_UUID, STA_ID, matieres } = body;
        if (!USE_UUID) {
            return res.status(400).json({ status: 'error', message: 'User id is required' });
        }
        if (!STA_ID) {
            return res.status(400).json({ status: 'error', message: 'Status id is required' });
        }
        if (!matieres || !Array.isArray(matieres)) {
            return res.status(400).json({ status: 'error', message: 'Matiere id is required' });
        }

        const updateProfSQL = "UPDATE ICA_Prof SET STA_ID = ? WHERE USE_UUID = ?";
        await this.appService.executeSql(updateProfSQL, [STA_ID, USE_UUID]);

        const deleteResponsableSQL = "DELETE FROM ICA_Responsable WHERE USE_UUID = ?";
        await this.appService.executeSql(deleteResponsableSQL, [USE_UUID]);

        for (const matiere of matieres[0].split(',')) {
            if (matiere.length === 0) {
                continue;
            }
            const insertResponsableSQL = "INSERT INTO ICA_Responsable (USE_UUID, MAT_ID) VALUES (?, ?)";
            await this.appService.executeSql(insertResponsableSQL, [USE_UUID, matiere]);
        }

        return res.json({ status: 'success', message: 'Prof updated successfully' });
    }

    @Post('/api/salle/edit')
    async editSalle(@Body() body: any, @Res() res: Response, @Req() req: Request & { session: any }) {
        if (!await this.appService.hasAdminPermission(req.session['uuid'], 9)) {
            return res.status(403).json({ status: 'error', message: 'You do not have permissions to manage class' });
        }
        if (body.SAL_ID) {
            if (body.type) {
                const deleteTypeSQL = "DELETE FROM ICA_EST_TYPE WHERE SAL_ID = ?";
                await this.appService.executeSql(deleteTypeSQL, [body.SAL_ID]);

                for (const type of body.type[0].split(',')) {
                    if (type.length === 0) {
                        continue;
                    }
                    const insertTypeSQL = "INSERT INTO ICA_EST_TYPE(SAL_ID, TYP_ID) VALUES (?, ?)";
                    await this.appService.executeSql(insertTypeSQL, [body.SAL_ID, type]);
                }
            }
            if (body.utilisable) {
                const deleteUtilisableSQL = "DELETE FROM ICA_Autorise WHERE SAL_ID = ?";
                await this.appService.executeSql(deleteUtilisableSQL, [body.SAL_ID]);

                for (const utilisable of body.utilisable[0].split(',')) {
                    if (utilisable.length === 0) {
                        continue;
                    }
                    const insertUtilisableSQL = "INSERT INTO ICA_Autorise(SAL_ID, ETU_ID) VALUES (?, ?)";
                    await this.appService.executeSql(insertUtilisableSQL, [body.SAL_ID, utilisable]);
                }
            }
            return res.json({ status: 'success', message: 'Salle updated successfully' });
        } else {
            return res.status(400).json({ status: 'error', message: 'SAL_ID is required' });
        }
    }
}
