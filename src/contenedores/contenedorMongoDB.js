import mongoose from 'mongoose'
import {HOST_MONGO, PORT_MONGO, NODE_ENV} from '../../configEntorno.js'
import {logueoError}from '../../confWinston.js';

class ContenedorMongoDb{
    constructor(nombreColleccion, Schema){
        this.colleccion = mongoose.model(nombreColleccion, Schema)
    }

    static async iniciarPersistencia(){
        try {
            let url;
            if (NODE_ENV=='desarrollo') {
                url = `mongodb://${HOST_MONGO}:${PORT_MONGO}/ecommerce` 
                console.log('Mongo conectado local')
            }else{
                url = `mongodb+srv://Juan1978:Juan1978@cluster0.gwdrp.mongodb.net/?retryWrites=true&w=majority` 
                console.log('Mongo ATLAS conectado')
            }
            await mongoose.connect(url)
            console.log('Base de datos MongoDB conectada')
        } catch (error) {
            logueoError('Error en la conexion de MongoDB: ', error)
        }
    }

    async leer(id){
        let parametroBusqueda = {}
        let tipoDeArgumento;
        if(id){
            if (id.length==24) {
                tipoDeArgumento = 'ID'
                parametroBusqueda = {'_id' :id}  
            }else{
                tipoDeArgumento = 'OBJETO'
                parametroBusqueda=id
            }
        }else{
            tipoDeArgumento = 'VACIO'
        }
        try {
            console.log(tipoDeArgumento)
            const productos= await this.colleccion.find(parametroBusqueda, {__v:0})
            return productos
        } catch (error) {
            logueoError(`Este es el error en MONGO-LEER con Argumento: ${tipoDeArgumento}`, error)
        }
    }
    async guardar(datos) {
        try {
            let productoAgregado = await this.colleccion.create(datos)
            return productoAgregado
        } catch (error) {
            logueoError(`Este es el error en MONGO-GUARDAR: `, error)
        }
    }
    async modificar(productoAnterior, productoModificado,tipoDeModificacion) {
        switch (tipoDeModificacion) {
            case '$set':
                try {
                    return await this.colleccion.updateOne(productoAnterior,{$set: productoModificado})
                } catch (error) {
                    logueoError(`Este es el error en MONGO-MODIFICAR-TIPO SET: `, error)
                }
            case '$push':
                try {
                    return await this.colleccion.updateOne(productoAnterior,{$push: productoModificado})
                } catch (error) {
                    logueoError(`Este es el error en MONGO-MODIFICAR-TIPO PUSH: `, error)
                }
            default:
                break;
        }
        
        try {
            return await this.colleccion.updateOne(productoAnterior,productoModificado)
        } catch (error) {
            logueoError(`Este es el error en MONGO-MODIFICAR por DEFAULT: `, error)
        }
    }

    async eliminar(id){
        try {
            let parametroBusqueda = {'_id' :id} 
            const productos= await this.colleccion.deleteOne(parametroBusqueda)
            return productos
        } catch (error) {
            logueoError(`Este es el error en MONGO-ELIMINAR: `, error)
        }
    }




}
export default ContenedorMongoDb