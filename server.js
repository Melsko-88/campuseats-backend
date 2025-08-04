require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'campuseats_secret_key_2024';

app.use(cors({
  origin: [
    'https://ton-domaine.com',
    'https://www.ton-domaine.com',
    'http://localhost:3000'
  ],
  credentials: true
}));

app.use(helmet());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = {
  users: [
    {
      id: 1,
      email: 'marie.dupont@univ.fr',
      password: '$2b$10$8K1p/a0dclxKOktjNhDYzeUslkh1Oa4VEFLfgOQU9jzb85bZtdCve',
      name: 'Marie Dupont',
      campus: 'Université Paris-Saclay',
      year: 'L3 Informatique',
      loyaltyPoints: 127,
      totalOrders: 47,
      createdAt: new Date()
    }
  ],
  restaurants: [
    {
      id: 1,
      name: 'Pizzeria Campus',
      description: 'Pizzas italiennes • Pâtes • Salades',
      image: '🍕',
      rating: 4.7,
      prepTime: '8-12 min',
      isOpen: true,
      menu: [
        { id: 1, name: 'Pizza Margherita', description: 'Tomates, mozzarella, basilic', price: 12.50, category: 'Pizza', image: '🍕' },
        { id: 2, name: 'Pâtes Carbonara', description: 'Pâtes fraîches, lardons, parmesan', price: 9.80, category: 'Pâtes', image: '🍝' },
        { id: 3, name: 'Salade César', description: 'Salade, poulet, croûtons, parmesan', price: 8.50, category: 'Salade', image: '🥗' },
        { id: 4, name: 'Coca-Cola', description: '33cl', price: 2.50, category: 'Boisson', image: '🥤' }
      ]
    },
    {
      id: 2,
      name: 'Green & Fresh',
      description: 'Salades • Bowls • Smoothies',
      image: '🥗',
      rating: 4.9,
      prepTime: '5-8 min',
      isOpen: true,
      menu: [
        { id: 5, name: 'Bowl Healthy', description: 'Quinoa, avocat, légumes de saison', price: 11.90, category: 'Bowl', image: '🥗' },
        { id: 6, name: 'Smoothie Détox', description: 'Épinards, pomme, concombre, citron', price: 5.50, category: 'Boisson', image: '🥤' }
      ]
    }
  ],
  orders: [],
  orderCounter: 1000
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token d\'accès requis' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalide' });
    }
    req.user = user;
    next();
  });
};

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, campus, year } = req.body;

    const existingUser = db.users.find(user => user.email === email);
    if (existingUser) {
      return res.status(400).json({ error: 'Cet email est déjà utilisé' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: db.users.length + 1,
      email,
      password: hashedPassword,
      name,
      campus,
      year,
      loyaltyPoints: 0,
      totalOrders: 0,
      createdAt: new Date()
    };

    db.users.push(newUser);

    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Compte créé avec succès',
      token,
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        campus: newUser.campus,
        year: newUser.year,
        loyaltyPoints: newUser.loyaltyPoints
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la création du compte' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = db.users.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ error: 'Email ou mot de passe incorrect' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Email ou mot de passe incorrect' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Connexion réussie',
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        campus: user.campus,
        year: user.year,
        loyaltyPoints: user.loyaltyPoints,
        totalOrders: user.totalOrders
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la connexion' });
  }
});

app.get('/api/restaurants', (req, res) => {
  try {
    const restaurants = db.restaurants.map(restaurant => ({
      id: restaurant.id,
      name: restaurant.name,
      description: restaurant.description,
      image: restaurant.image,
      rating: restaurant.rating,
      prepTime: restaurant.prepTime,
      isOpen: restaurant.isOpen
    }));

    res.json({ restaurants });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des restaurants' });
  }
});

app.get('/api/restaurants/:id/menu', (req, res) => {
  try {
    const restaurantId = parseInt(req.params.id);
    const restaurant = db.restaurants.find(r => r.id === restaurantId);

    if (!restaurant) {
      return res.status(404).json({ error: 'Restaurant non trouvé' });
    }

    res.json({ menu: restaurant.menu });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération du menu' });
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { restaurantId, items, paymentMethod, specialInstructions } = req.body;
    const userId = req.user.userId;

    const restaurant = db.restaurants.find(r => r.id === restaurantId);
    if (!restaurant) {
      return res.status(404).json({ error: 'Restaurant non trouvé' });
    }

    let total = 0;
    const orderItems = [];

    for (const item of items) {
      const menuItem = restaurant.menu.find(m => m.id === item.id);
      if (!menuItem) {
        return res.status(400).json({ error: `Article non trouvé: ${item.id}` });
      }

      orderItems.push({
        id: menuItem.id,
        name: menuItem.name,
        price: menuItem.price,
        quantity: item.quantity || 1
      });

      total += menuItem.price * (item.quantity || 1);
    }

    const order = {
      id: ++db.orderCounter,
      userId,
      restaurantId,
      restaurant: {
        name: restaurant.name,
        image: restaurant.image
      },
      items: orderItems,
      total,
      paymentMethod,
      specialInstructions: specialInstructions || '',
      status: 'pending',
      estimatedTime: 10,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const qrData = {
      orderId: order.id,
      userId: userId,
      total: total,
      timestamp: new Date().toISOString()
    };

    const qrCodeUrl = await QRCode.toDataURL(JSON.stringify(qrData));
    order.qrCode = qrCodeUrl;

    db.orders.push(order);

    const user = db.users.find(u => u.id === userId);
    if (user) {
      user.loyaltyPoints += Math.floor(total);
      user.totalOrders += 1;
    }

    setTimeout(() => {
      const orderIndex = db.orders.findIndex(o => o.id === order.id);
      if (orderIndex !== -1) {
        db.orders[orderIndex].status = 'preparing';
        db.orders[orderIndex].updatedAt = new Date();
      }
    }, 2000);

    setTimeout(() => {
      const orderIndex = db.orders.findIndex(o => o.id === order.id);
      if (orderIndex !== -1) {
        db.orders[orderIndex].status = 'ready';
        db.orders[orderIndex].updatedAt = new Date();
      }
    }, order.estimatedTime * 60 * 1000);

    res.status(201).json({
      message: 'Commande créée avec succès',
      order: {
        id: order.id,
        restaurant: order.restaurant,
        items: order.items,
        total: order.total,
        status: order.status,
        estimatedTime: order.estimatedTime,
        qrCode: order.qrCode,
        createdAt: order.createdAt
      }
    });
  } catch (error) {
    console.error('Erreur création commande:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la commande' });
  }
});

app.get('/api/orders', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    const userOrders = db.orders
      .filter(order => order.userId === userId)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({ orders: userOrders });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des commandes' });
  }
});

app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    const user = db.users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        campus: user.campus,
        year: user.year,
        loyaltyPoints: user.loyaltyPoints,
        totalOrders: user.totalOrders
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération du profil' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'CampusEats API is running on Render!',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route non trouvée' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 CampusEats API démarrée sur le port ${PORT}`);
  console.log(`🌐 Prêt à servir les étudiants du campus!`);
});

module.exports = app;
