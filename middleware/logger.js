import fs from 'fs';
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';

import chalk from 'chalk';

const __filename = fileURLToPath(import.meta.url);
const PATH = dirname(__filename);
const filePath = path.join(PATH, '..', 'logs', 'log.txt');

const logger = (req, res, next) => {
    const { method, url } = req;

    const now = new Date();
    const year = now.getFullYear();
    let month = now.getMonth() + 1;
    let day = now.getDate();
    let hour = now.getHours();
    let minute = now.getMinutes();
    let second = now.getSeconds();

    month = month < 10 ? `0${month}` : month;
    day = day < 10 ? `0${day}` : day;
    hour = hour < 10 ? `0${hour}` : hour;
    minute = minute < 10 ? `0${minute}` : minute;
    second = second < 10 ? `0${second}` : second;

    const time = `${year}-${month}-${day} ${hour}:${minute}:${second}`;
    const logMessage = `${chalk.blue(time)} ------ ${chalk.green(
        method
    )} ----- ${chalk.yellow(url)}`;

    console.log(logMessage);

    const message = `${time} ------ ${method} ----- ${url}\n`;

    fs.appendFile(filePath, message, (err) => {
        if (err) {
            console.log(err);
        }
    });

    next();
};

export default logger;
