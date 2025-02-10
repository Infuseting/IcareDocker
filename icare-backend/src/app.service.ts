// icare-backend/src/app.service.ts
import { Injectable } from '@nestjs/common';
import { DataSource } from 'typeorm';
import * as fs from 'fs';
@Injectable()
export class AppService {
  constructor(private readonly dataSource: DataSource) {}

  async checkUserExists(uuid: string): Promise<boolean> {
    const result = await this.dataSource.query(
        'SELECT COUNT(*) as count FROM ICA_User WHERE USE_UUID = ?',
        [uuid]
    );
    return result[0].count > 0;
  }

  async hasAdminPermission(uuid: string, id: number): Promise<boolean> {
    const result = await this.dataSource.query(
        'SELECT * FROM ICA_USER_PERMISSION WHERE USE_UUID = ?',
        [uuid]
    );
    console.log(uuid);
    return result.some(row => row.PER_ID === id || row.PER_ID === 1);
  }

  async executeSql(query: string, params: any[]): Promise<any> {
    return this.dataSource.query(query, params);
  }
}

export class ICal {
  public todoCount: number = 0;
  public eventCount: number = 0;
  private cal: any = {};
  private lastKeyword: string = '';
  private initialized: Promise<void>;

  constructor(filename: string) {
    this.initialized = this.initialize(filename);
  }

  private async initialize(filename: string): Promise<void> {
    const response = await fetch(filename);
    const text = await response.text();
    const lines = text.split(/\r?\n/).filter(line => line.trim() !== '');
    let type: string = '';
    if (!lines[0].includes('BEGIN:VCALENDAR')) {
      throw new Error('Invalid iCal file');
    } else {
      for (const line of lines) {
        const trimmedLine = line.trim();
        const add = this.keyValueFromString(trimmedLine);
        if (add === false) {
          this.addCalendarComponentWithKeyAndValue(type, false, trimmedLine);
          continue;
        }
        const [keyword, value] = add;
        switch (trimmedLine) {
          case "BEGIN:VTODO":
            this.todoCount++;
            type = "VTODO";
            break;
          case "BEGIN:VEVENT":
            this.eventCount++;
            type = "VEVENT";
            break;
          case "BEGIN:VCALENDAR":
          case "BEGIN:DAYLIGHT":
          case "BEGIN:VTIMEZONE":
          case "BEGIN:STANDARD":
            type = value;
            break;
          case "END:VTODO":
          case "END:VEVENT":
          case "END:VCALENDAR":
          case "END:DAYLIGHT":
          case "END:VTIMEZONE":
          case "END:STANDARD":
            type = "VCALENDAR";
            break;
          default:
            this.addCalendarComponentWithKeyAndValue(type, keyword, value);
            break;
        }
      }
    }
  }

  public async events(): Promise<any[]> {
    await this.initialized;
    return this.cal['VEVENT'] || [];
  }

  public addCalendarComponentWithKeyAndValue(component: string, keyword: string | false, value: string): void {
    if (keyword === false) {
      keyword = this.lastKeyword;
      switch (component) {
        case 'VEVENT':
          if (!this.cal[component]) {
            this.cal[component] = [];
          }
          if (!this.cal[component][this.eventCount - 1]) {
            this.cal[component][this.eventCount - 1] = {};
          }
          value = this.cal[component][this.eventCount - 1][keyword] + value;
          break;
        case 'VTODO':
          if (!this.cal[component]) {
            this.cal[component] = [];
          }
          if (!this.cal[component][this.todoCount - 1]) {
            this.cal[component][this.todoCount - 1] = {};
          }
          value = this.cal[component][this.todoCount - 1][keyword] + value;
          break;
      }
    }

    if (keyword.includes("DTSTART") || keyword.includes("DTEND")) {
      keyword = keyword.split(";")[0];
    }

    switch (component) {
      case "VTODO":
        if (!this.cal[component]) {
          this.cal[component] = [];
        }
        if (!this.cal[component][this.eventCount - 1]) {
          this.cal[component][this.eventCount - 1] = {};
        }
        this.cal[component][this.todoCount - 1][keyword] = value;
        break;
      case "VEVENT":
        if (!this.cal[component]) {
          this.cal[component] = [];
        }
        if (!this.cal[component][this.eventCount - 1]) {
          this.cal[component][this.eventCount - 1] = {};
        }
        this.cal[component][this.eventCount - 1][keyword] = value;
        break;
      default:
        if (!this.cal[component]) {
          this.cal[component] = {};
        }
        this.cal[component][keyword] = value;
        break;
    }
    this.lastKeyword = keyword;
  }

  private keyValueFromString(text: string): [string, string] | false {
    const matches = text.match(/([^:]+):([\w\W]*)/);
    if (!matches) {
      return false;
    }
    return [matches[1], matches[2]];
  }

  private iCalDateToUnixTimestamp(icalDate: string): number | false {
    icalDate = icalDate.replace('T', '').replace('Z', '');

    const pattern = /([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{0,2})([0-9]{0,2})([0-9]{0,2})/;
    const date = icalDate.match(pattern);

    if (!date || date[1] <= '1970') {
      return false;
    }

    return new Date(
        parseInt(date[1]),
        parseInt(date[2]) - 1,
        parseInt(date[3]),
        parseInt(date[4]) || 0,
        parseInt(date[5]) || 0,
        parseInt(date[6]) || 0
    ).getTime() / 1000;
  }

  public async eventsFromRange(rangeStart: Date | false = false, rangeEnd: Date | false = false): Promise<any[] | false> {
    await this.initialized;
    const events = this.sortEventsWithOrder(await this.events(), 'asc');

    if (!events) {
      return false;
    }

    const extendedEvents: any[] = [];

    if (!rangeStart) {
      rangeStart = new Date();
    }

    if (!rangeEnd || rangeEnd <= new Date(0)) {
      rangeEnd = new Date('2038-01-18');
    }

    const rangeStartTimestamp = rangeStart.getTime() / 1000;
    const rangeEndTimestamp = rangeEnd.getTime() / 1000;

    for (const event of events) {
      const timestamp = this.iCalDateToUnixTimestamp(event['DTSTART']);
      if (timestamp && timestamp >= rangeStartTimestamp && timestamp <= rangeEndTimestamp) {
        extendedEvents.push(event);
      }
    }

    return extendedEvents;
  }

  public sortEventsWithOrder(events: any[], sortOrder: 'asc' | 'desc' = 'asc'): any[] {
    const extendedEvents = events.map(event => {
      if (!event['UNIX_TIMESTAMP']) {
        event['UNIX_TIMESTAMP'] = this.iCalDateToUnixTimestamp(event['DTSTART']);
      }
      if (!event['REAL_DATETIME']) {
        event['REAL_DATETIME'] = new Date(event['UNIX_TIMESTAMP'] * 1000).toLocaleDateString();
      }
      return event;
    });

    return extendedEvents.sort((a, b) => {
      if (sortOrder === 'asc') {
        return a['UNIX_TIMESTAMP'] - b['UNIX_TIMESTAMP'];
      } else {
        return b['UNIX_TIMESTAMP'] - a['UNIX_TIMESTAMP'];
      }
    });
  }
}