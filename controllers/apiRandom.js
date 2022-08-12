/* import { fork } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
 */
import {calculo} from './childProcess.js'
import {arg} from '../servidorHBS.js'

const apiRandom = (req, res) => {
    const cant = req.query.cant
/*     console.log('arg.CLUSTER')
    console.log(arg.CLUSTER)

    if (!arg.cluster&&!arg.CLUSTER&&!arg.FORK&&!arg.fork)  {

//EN MODO FORK NATIVO (c/node, nodemon o forever) SE LEVANTA UN CHILD PROCESS ANTES DE EJECUTAR CALCULO
//EL ARGUMENTO arg.FORK SOLO SE AGREGA CUANDO SE USA PM2 FORK +CLUSTER 

    const child = fork(__dirname + '/childProcess.js')
        child.send(`${cant}`) 
        child.on('message', obj=>{
            res.send( `PUERTO: ${arg.port}, PID: ${child.pid}
               `+ JSON.stringify(obj)); 
            console.log(child.pid)
            child.kill()
        })
    } else{
                //EN MODO CLUSTER NATIVO o CLUSTER + FORK de PM2 SE EJECUTA DIRECTAMENTE

 */       
    const cantParse = (Number(cant))
    let objeto;
    if (!isNaN(cantParse)) {
        objeto = calculo(cant)
    } else {
        objeto = calculo(1e8)
    }
    res.send( `PUERTO: ${arg.port}, PID: ${process.pid}   `+ JSON.stringify(objeto)); 
}   
//}
export default apiRandom
