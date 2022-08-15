import fs from 'fs'
import express, {Router} from 'express';
import multer from 'multer';
import exphbs from 'express-handlebars';
import {Server as HttpServer} from "http";
import {Server as IOServer} from "socket.io";
import lista from './prodAleatorios.js'
import {daoMensaje, daoUsuario } from './src/index.js';
import normalizado from './normalizado.js'
import session from 'express-session';
import bcrypt from 'bcrypt';
import passport from 'passport';
import {Strategy as LocalStrategy} from 'passport-local';
import apiRandom from './controllers/apiRandom.js'
import {cpus as numCPUS} from 'os'
import cluster from 'cluster';
import compression from 'compression';
import {logueoWarning,logueoInfo, logueoError}from './confWinston.js';
import {PORT,arg} from './configEntorno.js'

//------------SETEO DE SERVER----------
const app= express(); 
const httpServer = new HttpServer(app) 
const io = new IOServer(httpServer)

//--------------ROUTER PARA NUMEROS ALEATORIOS-----------
const routerApiRandoms = Router()
app.use('/api/randoms',routerApiRandoms)
routerApiRandoms.use(express.json())
routerApiRandoms.use(express.urlencoded({extended: true})) 

//--------------SETEO DE VISTAS------------
app.engine('handlebars',exphbs.engine())
app.use(express.static('views'))
app.set('view engine','handlebars')
app.set('views', './views')
app.use(express.json())
app.use(express.urlencoded({extended: true})) 

//-----------SETEO DE PASSPORT-SESION---------
app.use(session({
  
  secret: 'secreto', 
  cookie:{
    httpOnly:false,
    secure:false,
    //maxAge: 60000 * 10 // 10 MINUTOS
  },  
  rolling:true,
  resave:true,
  saveUninitialized:false,
}))  
app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser((username,done)=>done(null, username.username))
passport.deserializeUser((username,done)=>{
  done(null, username)}
)

//--------------PASSPORT STRATEGIES-----------
//--------------------------------------------

//---------------STRATEGY DE REGISTRO------------
passport.use('registro', new LocalStrategy({
  passReqToCallback:true
  }, async (req,username,password,done)=>{
  let user;
  try {
    [user] = await daoUsuario.leer({username}) 
    console.log(`Lectura de registros correcta`)
  } catch (error) {
    logueoError(`Este es el error al leer registros de BD: ` , error)
  }
  if (user) {
    logueoError('Usuario ya registrado')
    try {
      await fs.promises.unlink(`./views/avatares/${req.file.filename}`)
      console.log('Borrado de avatar exitoso')
    } catch (error) {
      logueoError(`Error al borrar imagen: ${error} `)
    }
    return done(null, false)
  }
  
  const usuarioNuevo= {
    nombre:req.body.nombre,
    edad:req.body.edad,
    direccion:req.body.direccion,
    telefono: req.body.phone,
    urlImagen:req.file.filename,
    username: username,
    password: bcrypt.hashSync(password, bcrypt.genSaltSync(10))
  }
  console.log(usuarioNuevo)
  try {
   await daoUsuario.guardar(usuarioNuevo)
   console.log('REGISTRO EXITOSO')
  } catch (error) {
    logueoError('Este es  el error al guardar usuarioNuevo: ', error)
  }

  return done(null, usuarioNuevo)
}))  

//---------------STRATEGY DE LOGUEO------------
passport.use('logueo', new LocalStrategy( async (username,password,done)=>{
  let user;
  try {
    [user]= (await daoUsuario.leer({username}))    
    
  } catch (error) {
    logueoError('Este es  el error al leer usuario en logueo: ', error) 
    return done(null, false)
  }
  if(!user || !bcrypt.compareSync(password, user.password)){
    logueoError('Usuario no encontrado')
    return done(null, false)
  }
  
  console.log('LOGUEO EXITOSO')
  return done(null, user)
})) 

//---------------MIDDLEWARE DE AUTENTICACION y deMULTER PARA GUARDAR IMAGENES--------------------  
function auth(req, res, next){
  if (req.isAuthenticated()) {
    console.log('USUARIO AUTENTICADO') 
    next()
  }else{
    logueoError('USUARIO NO AUTENTICADO, DEBE LOGUEARSE')
    res.redirect('/login')
  }
}
let avatar = multer.diskStorage({
  destination:(req,file,cb)=>{
    cb(null,'./views/avatares')
  },
  filename:(req,file,cb)=>{
    cb(null,`${Date.now()}-${file.originalname}`)
  }
})
const upload = multer({storage:avatar})

//------------------------------RUTAS---------------------------------

//-------------REGISTRO--------------
const passportAuthRegister =passport.authenticate('registro',{failureRedirect:'/errorRegistro'})  

app.get('/register',logueoInfo, (req, res) => {
  res.render("register");
})  

app.post('/register', upload.single('imagen'), passportAuthRegister,logueoInfo, (req, res) => {
  const nombreMayus= req.body.nombre.toUpperCase()
  req.session.nombre= nombreMayus
  req.session.urlImagen=req.file.filename
  res.redirect('/centroMensajes')
})  

app.get('/errorRegistro',logueoInfo,(req, res) => {
  res.render("errorRegistro");
})  

//-------------LOGUEO----------------
const passportAuthLogin=  passport.authenticate('logueo',{failureRedirect:'/errorLogin'})

app.get('/', auth, logueoInfo, (req, res) => {
  res.redirect('/centroMensajes')
})

app.get('/login', logueoInfo, (req, res) => {
  res.render("login");
})

app.post('/login', passportAuthLogin, logueoInfo, async (req, res) => {

  const [{nombre,urlImagen}]= await daoUsuario.leer({username: req.body.username})
  console.log(nombre)
  const nombreMayus= nombre.toUpperCase()
  req.session.nombre= nombreMayus
  req.session.urlImagen= urlImagen
  res.redirect('/centroMensajes')
})

app.get('/errorLogin',logueoInfo, (req, res) => {
  res.render('errorLogin')
})

//--------------DESLOGUEO--------
app.get('/logout',auth, logueoInfo,(req, res) => {
  req.session.destroy((err)=>{
    if (!err) {
      setTimeout(()=>{
       return res.redirect('login') 
      },2000) 
    } else {
      logueoError('Este es el error en LOGOUT: ', error)
        res.send('ERROR EN LOGOUT', err )
    }    
    console.log('Te deslogueaste con exito')})
})    

//-------------CENTRO DE MENSAJES-- (PAGINA PRINCIPAL) -----------

app.get('/centroMensajes', auth , logueoInfo,(req, res) => {
  console.log(req.session.urlImagen)
  const usuario = {
    nombre:req.session.nombre,
    urlImagen:req.session.urlImagen,

    email:req.user,
  }
  res.render("centroMensajes",usuario);
})

//-------------RUTA INFORMACION---------------

const info ={
  argumentos: JSON.stringify(arg),
  sistema:process.platform,
  versionNode:process.version,  
  memoria:process.memoryUsage().rss,
  pathEjecucion:process.execPath,
  proccessId:process.pid,
  carpetaProyecto:process.cwd(),
  cantProcesadores:numCPUS().length
}

app.get('/info', logueoInfo, (req, res) => {
  info.compIsTrue = 'No Comprimida'
  //console.log(info) 
  res.render("info",info)
})
app.get('/infoComp', compression(), logueoInfo, (req, res) => {
  info.compIsTrue = 'Comprimida'
  res.render("info",info)
})

//-------------GET DE NUMEROS ALEATORIOS -----------

routerApiRandoms.get('/',logueoInfo, apiRandom)

//-------------GET DE PRODUCTOS ALEATORIOS -----------

app.get('/api/productos-test',auth, logueoInfo,(req, res) => {
    
  let tablaProductos=lista()
  res.render("tablaAleatoria", {tablaProductos});
})

//------------------WEBSOCKETS------------------------------

let mensajes1=[]
let mensajesNormalizados;

io.on("connection", (socket) => { 
  console.log("Usuario Conectado");

  if (!mensajes1.length) {
    mensajesNormalizados=[]
  } else {
    mensajesNormalizados= normalizado(mensajes1)
  }
  
  socket.emit("mensajes",mensajesNormalizados);
  
  socket.on("mensajeNuevo", (newMessage) => {
    mensajes1.push(newMessage);
    mensajesNormalizados= normalizado(mensajes1)

    daoMensaje.guardar(newMessage)
    io.sockets.emit("mensajes", mensajesNormalizados);
  });
});

//-------------RUTAS POR DEFAULT------------

const errorRuta= {error: -2, descripcion: `ruta no implementada`}

app.all('*', logueoWarning,(req,res)=>{
  res.json(errorRuta)
  })

//---------------SERVER LISTEN------------------------------

if (!arg.CLUSTER&&!arg.cluster) {
  console.log('MODO FORK')
  const connectedServer = httpServer.listen(PORT, () => {
    console.log(`Servidor con Websockets en el puerto ${connectedServer.address().port}`);
  });
  connectedServer.on("error", (error) =>   
  logueoError(`El error en server fue el siguiente: `, error)  
  );  

} else {
  console.log('MODO CLUSTER')      

  if (cluster.isPrimary) {
  console.log(`Proceso Master ${process.pid} Iniciado`);

    for (let i = 0; i < numCPUS().length; i++) {
      cluster.fork();
    }
    cluster.on('exit', (worker) => {
      console.log(`worker ${worker.process.pid} murio`);
      cluster.fork();
    });
  }else{
    console.log(`Proceso Worker ${process.pid} Iniciado`);
    
    const connectedServer = httpServer.listen(PORT, () => {
      console.log(`Servidor con Websockets en el puerto ${connectedServer.address().port}`);
    });
    connectedServer.on("error", (error) =>
    logueoError(`El error en server fue el siguiente: `, error)  
    );
  } 
} 
             
console.log(arg) 