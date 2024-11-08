const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const bodyParser = require('body-parser');
const app = express();
const PORT = process.env.PORT || 3001;
const path = require('path');
const crypto = require('crypto');

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Servir la carpeta de 'uploads' de manera estática
app.use('/uploads', express.static('uploads'));

// Base de datos
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'aloradtbs' 
});

// Configuración de Multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Carpeta donde se almacenan las imágenes
    },
    filename: (req, file, cb) => {
      //Nombre aleatorio y único para la imagen
        const uniqueSuffix = crypto.randomBytes(16).toString('hex');
      // Obtener la extensión del archivo
        const extension = path.extname(file.originalname); 
      // Guardar el archivo con un nombre aleatorio y su extensión original
        cb(null, `${uniqueSuffix}${extension}`);
    }
});

// Conectar a la base de datos
db.connect(err => {
    if (err) {
        console.error('Error conectando a la base de datos:', err);
        return;
    }
    console.log('Conectado a la base de datos MySQL');
});

//----------------------------------------------------Visitante-----------------------------------------------------------

// Ruta para obtener los productos recientemente agregados
app.get('/api/recent-products', (req, res) => {
    const query = 'SELECT * FROM producto ORDER BY fecha_publicacion DESC LIMIT 10';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener productos recientes:', err);
            return res.status(500).json({ error: 'Error al obtener productos recientes' });
        }
        res.json(results);
    });
});

// Ruta para buscar productos
app.get('/api/search', (req, res) => {
    const searchTerm = req.query.query;
    if (!searchTerm) {
        return res.status(400).json({ error: 'No se proporcionó término de búsqueda' });
    }
    const searchQuery = `
        SELECT * FROM producto 
        WHERE nombre LIKE ? OR descripcion LIKE ?
    `;
    const searchValue = `%${searchTerm}%`;
    db.query(searchQuery, [searchValue, searchValue], (err, results) => {
        if (err) {
            console.error('Error en la búsqueda:', err);
            return res.status(500).json({ error: 'Error al buscar productos' });
        }
        res.json(results);
    });
});


// Ruta para obtener detalles de un producto por ID
app.get('/api/producto/:id', (req, res) => {
    const productId = req.params.id;
    const query = 'SELECT * FROM producto WHERE id = ?';
    db.query(query, [productId], (err, results) => {
        if (err) {
            console.error('Error al obtener el producto:', err);
            return res.status(500).json({ error: 'Error al obtener el producto' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Producto no encontrado' });
        }
        res.json(results[0]);
    });
});

// Ruta para registrar un nuevo usuario
app.post('/api/register', (req, res) => {
    const { nombres, apellidos, correo_electronico, contraseña } = req.body;
    const checkUserQuery = 'SELECT * FROM usuarios WHERE correo_electronico = ?';
    db.query(checkUserQuery, [correo_electronico], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error del servidor al verificar el usuario' });
        }
        if (result.length > 0) {
            return res.status(400).json({ error: 'El correo electrónico ya está registrado' });
        }
        // Encriptar la contraseña
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(contraseña, salt);
        // Insertar nuevo usuario
        const insertQuery = 'INSERT INTO usuarios (nombres, apellidos, correo_electronico, contraseña, rol) VALUES (?, ?, ?, ?, ?)';
        db.query(insertQuery, [nombres, apellidos, correo_electronico, hashedPassword, 'usuario'], (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Error al registrar el usuario, intenta nuevamente' });
            }
            // Obtener el ID del nuevo usuario
            const newUserId = result.insertId;
            res.status(201).json({ message: 'Usuario registrado con éxito', userId: newUserId });
        });
    });
});

// Ruta para iniciar sesión
app.post('/api/login', (req, res) => {
    const { correo_electronico, contraseña } = req.body;
    const query = 'SELECT * FROM usuarios WHERE correo_electronico = ?';
    db.query(query, [correo_electronico], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error del servidor al iniciar sesión' });
        }
        if (result.length === 0) {
            return res.status(400).json({ error: 'El usuario no existe' });
        }
        const user = result[0];
        // Verificar la contraseña
        const isPasswordValid = bcrypt.compareSync(contraseña, user.contraseña);
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Contraseña incorrecta' });
        }
        // Crear y devolver un token
        const token = jwt.sign({ id: user.id, correo_electronico: user.correo_electronico }, 'secreto_del_token', { expiresIn: '1h' });
        // Enviar el token y el ID del usuario en la respuesta
        res.json({ token, userId: user.id });
    });
});

//----------------------------------------------------Usuario------------------------------------------------------------

//Datos del usuario
app.get('/api/user/:id', (req, res) => {
    const userId = req.params.id;
    const query = 'SELECT nombres, apellidos, correo_electronico, telefono, direccion FROM usuarios WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error al obtener la información del usuario:', err);
            return res.status(500).json({ error: 'Error al obtener la información del usuario' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        res.json(results[0]);
    });
});

//Actualizar datos del usuario
app.put('/api/user/:id', (req, res) => {
    const userId = req.params.id;
    const { nombres, apellidos, correo_electronico, telefono, direccion } = req.body;
    const query = `
        UPDATE usuarios 
        SET nombres = ?, apellidos = ?, correo_electronico = ?, telefono = ?, direccion = ?
        WHERE id = ?
    `;
    db.query(query, [nombres, apellidos, correo_electronico, telefono, direccion, userId], (err, results) => {
        if (err) {
            console.error('Error al actualizar la información del usuario:', err);
            return res.status(500).json({ error: 'Error al actualizar la información del usuario' });
        }
        res.json({ message: 'Información del usuario actualizada con éxito' });
    });
});

//Comprar productos
app.post('/api/comprar', (req, res) => {
    const { usuario_id, producto_id, cantidad_comprada, nombre_producto, descripcion_producto, imagen_principal, precio_total, direccion_envio } = req.body;
    if (!usuario_id || !producto_id || !cantidad_comprada || !direccion_envio) {
        return res.status(400).json({ message: 'Faltan datos para realizar la compra' });
    }
    // Consulta para verificar si el producto existe y la cantidad disponible
    const verificarProductoQuery = 'SELECT cantidad FROM producto WHERE id = ?';
    db.query(verificarProductoQuery, [producto_id], (err, result) => {
        if (err) {
            console.error('Error al verificar el producto:', err);
            return res.status(500).json({ error: 'Error del servidor al verificar el producto' });
        }
        const producto = result[0];
        if (!producto) {
            return res.status(404).json({ error: 'Producto no encontrado' });
        }
        if (producto.cantidad < cantidad_comprada) {
            return res.status(400).json({ message: 'No hay suficiente stock para completar la compra' });
        }
        //Insertar el registro de compra
        const registrarCompraQuery = `
        INSERT INTO pedidos (usuario_id, producto_id, nombre_producto, descripcion_producto, cantidad, imagen_principal, precio_total, direccion_envio) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        db.query(registrarCompraQuery, [usuario_id, producto_id, nombre_producto, descripcion_producto, cantidad_comprada, imagen_principal, precio_total, direccion_envio], (err, compraResult) => {
            if (err) {
                console.error('Error al registrar la compra:', err);
                return res.status(500).json({ error: 'Error del servidor al registrar la compra' });
            }
            // Si la compra se registra correctamente, reducir la cantidad del producto en stock
            const actualizarStockQuery = 'UPDATE producto SET cantidad = cantidad - ? WHERE id = ?';
            db.query(actualizarStockQuery, [cantidad_comprada, producto_id], (err, updateResult) => {
                if (err) {
                    console.error('Error al actualizar el stock:', err);
                    return res.status(500).json({ error: 'Error del servidor al actualizar el stock' });
                }
                res.status(201).json({ message: 'Compra realizada con éxito y stock actualizado' });
            });
        });
    });
});

//Pedido del usuario
app.get('/api/pedidos/:userId', (req, res) => {
    const userId = req.params.userId;
    const query = `SELECT * FROM pedidos WHERE usuario_id = ?`;
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error al obtener los pedidos:', err);
            return res.status(500).json({ error: 'Error al obtener los pedidos' });
        }
        res.json(results);
    });
});

//----------------------------------------------------Vendedor-----------------------------------------------------------

// Multer para subir una imagen
const upload = multer({ storage: storage }).fields([
    { name: 'imagen1', maxCount: 1 },
    { name: 'imagen2', maxCount: 1 },
    { name: 'imagen3', maxCount: 1 },
    { name: 'imagen4', maxCount: 1 },
    { name: 'imagen5', maxCount: 1 }
]);

// Ruta para publicar los productos
app.post('/api/sell', upload, (req, res) => {
    const { nombre, descripcion, precio, cantidad, usuario_id } = req.body;
    const imagenes = req.files;
    // Verificar si se recibieron las imágenes
    if (!nombre || !descripcion || !precio || !imagenes || !usuario_id) {
    return res.status(400).json({ message: 'Faltan datos en el formulario' });
    }
    // Guardar solo los nombres de las imágenes en la base de datos
    const imagen_principal = imagenes['imagen1'] ? `uploads/${imagenes['imagen1'][0].filename}` : null;
    const imagen_segundaria = imagenes['imagen2'] ? `uploads/${imagenes['imagen2'][0].filename}` : null;
    const imagen_terciaria = imagenes['imagen3'] ? `uploads/${imagenes['imagen3'][0].filename}` : null;
    const imagen_cuarta = imagenes['imagen4'] ? `uploads/${imagenes['imagen4'][0].filename}` : null;
    const imagen_quinta = imagenes['imagen5'] ? `uploads/${imagenes['imagen5'][0].filename}` : null;
    const query = `
    INSERT INTO producto (nombre, descripcion, precio, imagen_principal, imagen_segundaria, imagen_terciaria, imagen_cuarta, imagen_quinta, cantidad, usuario_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    db.query(query, [nombre, descripcion, precio, imagen_principal, imagen_segundaria, imagen_terciaria, imagen_cuarta, imagen_quinta, cantidad, usuario_id], (err, result) => {
    if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error al publicar el producto' });
    }
    res.status(201).json({ message: 'Producto publicado exitosamente' });
    });
});

// Ruta para obtener los productos publicados por el usuario
app.get('/api/mis-productos/:userId', (req, res) => {
    const userId = req.params.userId;
    const query = 'SELECT * FROM producto WHERE usuario_id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error al obtener los productos:', err);
            return res.status(500).json({ error: 'Error al obtener los productos' });
        }
        res.json(results);
    });
});

// Ruta para eliminar un producto
app.delete('/api/producto/:id', (req, res) => {
    const productId = req.params.id;
    const query = 'DELETE FROM producto WHERE id = ?';
    db.query(query, [productId], (err, result) => {
        if (err) {
            console.error('Error al eliminar el producto:', err);
            return res.status(500).json({ error: 'Error al eliminar el producto' });
        }
        res.json({ message: 'Producto eliminado exitosamente' });
    });
});

// Ruta para actualizar el estado del pedido
app.put('/api/pedido/:id/estado', (req, res) => {
    const pedidoId = req.params.id;
    const { estado } = req.body;
    const updateEstadoQuery = 'UPDATE pedidos SET estado = ? WHERE id = ?';
    db.query(updateEstadoQuery, [estado, pedidoId], (err, result) => {
        if (err) {
            console.error('Error al actualizar el estado del pedido:', err);
            return res.status(500).json({ error: 'Error al actualizar el estado del pedido' });
        }

        res.json({ message: 'Estado del pedido actualizado' });
    });
});

// Ruta para cancelar el pedido (y restaurar la cantidad del producto)
app.put('/api/pedido/:id/cancelar', (req, res) => {
    const pedidoId = req.params.id;
    // Obtener la cantidad y el producto relacionado con el pedido
    const getPedidoQuery = 'SELECT * FROM pedidos WHERE id = ?';
    db.query(getPedidoQuery, [pedidoId], (err, pedidoResult) => {
        if (err) {
            console.error('Error al obtener el pedido:', err);
            return res.status(500).json({ error: 'Error al obtener el pedido' });
        }
        if (pedidoResult.length === 0) {
            return res.status(404).json({ error: 'Pedido no encontrado' });
        }
        const pedido = pedidoResult[0];
        // Restaurar la cantidad del producto
        const updateProductQuery = 'UPDATE producto SET cantidad = cantidad + ? WHERE id = ?';
        db.query(updateProductQuery, [pedido.cantidad, pedido.producto_id], (err, productResult) => {
            if (err) {
                console.error('Error al restaurar la cantidad del producto:', err);
                return res.status(500).json({ error: 'Error al restaurar la cantidad del producto' });
            }
            // Actualizar el estado del pedido a 'cancelado'
            const updateEstadoQuery = 'UPDATE pedidos SET estado = "cancelado" WHERE id = ?';
            db.query(updateEstadoQuery, [pedidoId], (err, updateResult) => {
                if (err) {
                    console.error('Error al cancelar el pedido:', err);
                    return res.status(500).json({ error: 'Error al cancelar el pedido' });
                }
                res.json({ message: 'Pedido cancelado y cantidad restaurada' });
            });
        });
    });
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor escuchando en el puerto ${PORT}`);
});