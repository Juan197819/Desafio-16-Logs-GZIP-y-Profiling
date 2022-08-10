import winston from 'winston';

const logger = winston.createLogger({
    transports:[
        new winston.transports.Console({level:'info'}),
        new winston.transports.File({filename:'warn.log', level:'warn'}),
        new winston.transports.File({filename:'error.log', level:'error'})
    ]
})
export const logueoInfo = (req, res, next)=> {
    logger.info(`Ruta actual: ${req.originalUrl}, con metodo ${req.method} `)
    next()
}
export const logueoWarning = (req, res, next)=> {
    logger.warn(`Ruta actual: ${req.originalUrl}, con metodo ${req.method} `)
    next()
}
export const logueoError = (mensaje, error)=> {
    logger.error(mensaje, error)
}


export default logger