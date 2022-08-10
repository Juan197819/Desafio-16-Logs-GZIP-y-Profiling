import admin from 'firebase-admin'
import serviceAcount from '../../configFirebase.json' assert {type: "json"};
import {logueoError}from '../../confWinston.js';

let db;
class ContenedorFirebase{
    constructor(nombreColleccion){
        this.colleccion = db.collection(nombreColleccion)
    }
    
    static async iniciarPersistencia(){
        try {
            admin.initializeApp({
                credential: admin.credential.cert(serviceAcount)
            });
            db = admin.firestore()
            console.log('Base de datos FIREBASE conectada')
        } catch (error) {
            logueoError('Error en la conexion de FIREBASE', error)
        }
    }

    async leer(id){
        let tipoDeArgumento;
        if(id){
            if (id.length==20) {
                tipoDeArgumento = 'ID'
                console.log(tipoDeArgumento)
                try {
                    const doc= this.colleccion.doc(id)
                    const item= await doc.get()
                    let it= item.data()
                    !it? it= [] : it= [{_id: item.id,...it}]

                    return it
                } catch (error) {
                    logueoError(`Este es el error en FIREBASE-LEER-  con Argumento: ${tipoDeArgumento}`, error)
                }
            }else{
                tipoDeArgumento = 'OBJETO'
                console.log(tipoDeArgumento)
                try {
                    for (const key in id) {
                        const documentos= await this.colleccion.where(`${key}`, '==', `${id[key]}`).get(id)
                        const arraydocumentos= documentos.docs
                        const listaItem = arraydocumentos.map((e)=>{
                            return {_id: e.id,...(e.data())}
                        })
                        return listaItem
                    }
                } catch (error) {
                    logueoError(`Este es el error en FIREBASE-LEER-con Argumento: ${tipoDeArgumento}`, error)
                }
            }
        }else{
            tipoDeArgumento = 'VACIO'
            console.log(tipoDeArgumento)
            try {
                const documentos= await this.colleccion.get()
                const arraydocumentos= documentos.docs
                const listaItem = arraydocumentos.map((e)=>{
                    return {_id: e.id,...(e.data())}
                })
                return listaItem
            } catch (error) {
                logueoError(`Este es el error en FIREBASE-LEER con Argumento: ${tipoDeArgumento}`, error)
            }
        }      
    }

    async guardar(datos) {
        try {
            let productoAgregado = await this.colleccion.doc().create(datos)
            return productoAgregado
        } catch (error) {
            logueoError(`Este es el error en FIREBASE-GUARDAR`, error)
        }
    }

    async modificar(productoAnterior, productoModificado,tipoDeModificacion) {

        switch (tipoDeModificacion) {
            case '$set':
                try {
                    return await  this.colleccion.doc(productoAnterior._id).update(productoModificado)
                } catch (error) {
                    logueoError(`Este es el error en FIREBASE-MODIFICAR-TIPO SET: `, error)
                }
            case '$push':
                try {
                    productoAnterior.productos.push(productoModificado.productos)
                    return await  this.colleccion.doc(productoAnterior._id).update(productoAnterior)
                } catch (error) {
                    logueoError(`Este es el error en FIREBASE-MODIFICAR-TIPO PUSH: `, error)
                }
            default:
                break;
        }
        try {
            return await  this.colleccion.doc(productoAnterior._id).update(productoModificado)
        } catch (error) {
            logueoError(`Este es el error en FIREBASE-MODIFICAR por DEFAULT: `, error)
        }
    }

    async eliminar(id){
        try {
            const productos= await this.colleccion.doc(id).delete()
            return productos
        } catch (error) {
            logueoError(`Este es el error en FIREBASE-ELIMINAR: `, error)
        }
    }
}

export default ContenedorFirebase