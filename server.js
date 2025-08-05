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
  origin: '*',  // Autorise tous les domaines
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
      // HASH CORRIGÉ pour "password123"
      email: 'pizzeria@campus.fr',
      password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password123
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
      // HASH CORRIGÉ pour "password123"
      email: 'green@campus.fr',
      password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password123
      menu: [
        { id: 5, name: 'Bowl Healthy', description: 'Quinoa, avocat, légumes de saison', price: 11.90, category: 'Bowl', image: '🥗' },
        { id: 6, name: 'Smoothie Détox', description: 'Épinards, pomme, concombre, citron', price: 5.50, category: 'Boisson', image: '🥤' }
      ]
    }
  ],
  orders: [],
  orderCounter: 1000
};

// Middlewares d'authentification
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

// Middleware pour l'authentification restaurant
const authenticateRestaurant = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token d\'accès requis' });
  }

  jwt.verify(token, JWT_SECRET, (err, restaurant) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalide' });
    }
    if (!restaurant.restaurantId) {
      return res.status(403).json({ error: 'Token restaurant invalide' });
    }
    req.restaurant = restaurant;
    next();
  });
};

// ============================================
// ROUTES ÉTUDIANTS (existantes)
// ============================================

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

    const user = db.users.find(u => u.id === userId);
    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
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
        quantity: item.quantity || 1,
        customizations: item.customizations || []
      });

      total += menuItem.price * (item.quantity || 1);
    }

    const order = {
      id: ++db.orderCounter,
      userId,
      restaurantId,
      restaurant: {
        id: restaurant.id,
        name: restaurant.name,
        image: restaurant.image
      },
      student: {
        id: user.id,
        name: user.name,
        email: user.email
      },
      items: orderItems,
      total,
      paymentMethod,
      paymentStatus: paymentMethod === 'card' ? 'paid' : 'pending',
      specialInstructions: specialInstructions || '',
      status: 'pending',
      estimatedTime: 10,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    // Générer le QR code
    const qrData = {
      orderId: order.id,
      userId: userId,
      restaurantId: restaurantId,
      total: total,
      timestamp: new Date().toISOString()
    };

    const qrCodeUrl = await QRCode.toDataURL(JSON.stringify(qrData));
    order.qrCode = qrCodeUrl;

    db.orders.push(order);

    // Mettre à jour les points de fidélité
    user.loyaltyPoints += Math.floor(total);
    user.totalOrders += 1;

    // Simulation de progression automatique (optionnel pour démo)
    // setTimeout(() => {
    //   const orderIndex = db.orders.findIndex(o => o.id === order.id);
    //   if (orderIndex !== -1 && db.orders[orderIndex].status === 'pending') {
    //     db.orders[orderIndex].status = 'preparing';
    //     db.orders[orderIndex].updatedAt = new Date();
    //   }
    // }, 30000); // 30 secondes

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

// ============================================
// NOUVELLES ROUTES RESTAURANT
// ============================================

// Connexion restaurant
app.post('/api/restaurant/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('🔐 === DÉBUT CONNEXION RESTAURANT ===');
    console.log('📧 Tentative de connexion:', email);

    const restaurant = db.restaurants.find(r => r.email === email);
    if (!restaurant) {
      console.log('❌ Restaurant non trouvé avec email:', email);
      return res.status(400).json({ error: 'Email ou mot de passe incorrect' });
    }

    console.log('✅ Restaurant trouvé:', restaurant.name);
    console.log('🔐 Hash stocké:', restaurant.password);

    const isValidPassword = await bcrypt.compare(password, restaurant.password);
    console.log('🔍 Résultat bcrypt.compare:', isValidPassword);

    if (!isValidPassword) {
      console.log('❌ Mot de passe incorrect pour:', email);
      return res.status(400).json({ error: 'Email ou mot de passe incorrect' });
    }

    const token = jwt.sign(
      { 
        restaurantId: restaurant.id, 
        email: restaurant.email,
        name: restaurant.name
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('✅ Connexion restaurant réussie:', restaurant.name);
    console.log('🔐 === FIN CONNEXION RESTAURANT ===');

    res.json({
      message: 'Connexion restaurant réussie',
      token,
      restaurant: {
        id: restaurant.id,
        email: restaurant.email,
        name: restaurant.name,
        description: restaurant.description,
        image: restaurant.image,
        rating: restaurant.rating,
        isOpen: restaurant.isOpen
      }
    });
  } catch (error) {
    console.error('❌ Erreur connexion restaurant:', error);
    res.status(500).json({ error: 'Erreur lors de la connexion' });
  }
});

// Profil restaurant
app.get('/api/restaurant/profile', authenticateRestaurant, (req, res) => {
  try {
    const restaurantId = req.restaurant.restaurantId;
    const restaurant = db.restaurants.find(r => r.id === restaurantId);
    
    if (!restaurant) {
      return res.status(404).json({ error: 'Restaurant non trouvé' });
    }

    // Calculer les statistiques
    const restaurantOrders = db.orders.filter(order => order.restaurantId === restaurantId);
    const todayOrders = restaurantOrders.filter(order => {
      const orderDate = new Date(order.createdAt);
      const today = new Date();
      return orderDate.toDateString() === today.toDateString();
    });

    const todayRevenue = todayOrders
      .filter(order => order.paymentStatus === 'paid')
      .reduce((sum, order) => sum + order.total, 0);

    res.json({
      restaurant: {
        id: restaurant.id,
        name: restaurant.name,
        email: restaurant.email,
        description: restaurant.description,
        image: restaurant.image,
        rating: restaurant.rating,
        isOpen: restaurant.isOpen,
        stats: {
          todayOrders: todayOrders.length,
          todayRevenue: todayRevenue,
          totalOrders: restaurantOrders.length
        }
      }
    });
  } catch (error) {
    console.error('Erreur profil restaurant:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération du profil' });
  }
});

// Récupérer les commandes du restaurant
app.get('/api/restaurant/orders', authenticateRestaurant, (req, res) => {
  try {
    const restaurantId = req.restaurant.restaurantId;
    
    console.log('📋 Récupération commandes pour restaurant:', restaurantId);
    
    const restaurantOrders = db.orders
      .filter(order => order.restaurantId === restaurantId)
      .filter(order => order.status !== 'completed') // Exclure les commandes terminées
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    console.log(`📦 ${restaurantOrders.length} commandes trouvées`);

    res.json({ 
      orders: restaurantOrders,
      total: restaurantOrders.length
    });
  } catch (error) {
    console.error('❌ Erreur récupération commandes restaurant:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des commandes' });
  }
});

// Mettre à jour le statut d'une commande
app.put('/api/restaurant/orders/:id/status', authenticateRestaurant, (req, res) => {
  try {
    const orderId = parseInt(req.params.id);
    const { status } = req.body;
    const restaurantId = req.restaurant.restaurantId;

    console.log(`🔄 Mise à jour statut commande ${orderId} vers ${status}`);

    const orderIndex = db.orders.findIndex(order => 
      order.id === orderId && order.restaurantId === restaurantId
    );

    if (orderIndex === -1) {
      return res.status(404).json({ error: 'Commande non trouvée' });
    }

    const validStatuses = ['pending', 'preparing', 'ready', 'completed', 'rejected'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Statut invalide' });
    }

    // Mettre à jour le statut
    db.orders[orderIndex].status = status;
    db.orders[orderIndex].updatedAt = new Date();

    // Si la commande passe en "ready", calculer le temps de préparation réel
    if (status === 'ready') {
      const order = db.orders[orderIndex];
      const prepTime = Math.round((new Date() - new Date(order.createdAt)) / (1000 * 60));
      order.actualPrepTime = prepTime;
    }

    console.log(`✅ Commande ${orderId} mise à jour vers ${status}`);

    res.json({
      message: `Commande mise à jour vers ${status}`,
      order: db.orders[orderIndex]
    });
  } catch (error) {
    console.error('❌ Erreur mise à jour statut:', error);
    res.status(500).json({ error: 'Erreur lors de la mise à jour du statut' });
  }
});

// Scanner et valider un QR code
app.post('/api/restaurant/orders/scan', authenticateRestaurant, (req, res) => {
  try {
    const { qrCode } = req.body;
    const restaurantId = req.restaurant.restaurantId;

    console.log('📱 Scan QR Code par restaurant:', restaurantId);

    if (!qrCode) {
      return res.status(400).json({ error: 'QR Code requis' });
    }

    let qrData;
    try {
      // Le QR code contient les données JSON de la commande
      qrData = JSON.parse(qrCode);
    } catch (e) {
      return res.status(400).json({ 
        success: false, 
        error: 'QR Code invalide - format incorrect' 
      });
    }

    // Vérifier que le QR code contient les bonnes données
    if (!qrData.orderId) {
      return res.status(400).json({ 
        success: false, 
        error: 'QR Code invalide - données manquantes' 
      });
    }

    // Trouver la commande
    const orderIndex = db.orders.findIndex(order => 
      order.id === qrData.orderId && 
      order.restaurantId === restaurantId
    );

    if (orderIndex === -1) {
      return res.status(404).json({ 
        success: false, 
        error: 'Commande non trouvée ou non autorisée' 
      });
    }

    const order = db.orders[orderIndex];

    // Vérifier le statut de la commande
    if (order.status !== 'ready') {
      return res.status(400).json({ 
        success: false, 
        error: `Commande non prête (statut: ${order.status})` 
      });
    }

    // Vérifier si déjà récupérée
    if (order.status === 'completed') {
      return res.status(400).json({ 
        success: false, 
        error: 'Commande déjà récupérée' 
      });
    }

    // Marquer comme terminée
    db.orders[orderIndex].status = 'completed';
    db.orders[orderIndex].completedAt = new Date();
    db.orders[orderIndex].updatedAt = new Date();

    console.log(`✅ Commande ${order.id} récupérée avec succès`);

    res.json({
      success: true,
      message: 'QR Code validé avec succès',
      order: {
        id: order.id,
        student: order.student,
        items: order.items,
        total: order.total,
        status: 'completed'
      }
    });
  } catch (error) {
    console.error('❌ Erreur scan QR:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Erreur lors de la validation du QR Code' 
    });
  }
});

// Statistiques restaurant
app.get('/api/restaurant/stats', authenticateRestaurant, (req, res) => {
  try {
    const restaurantId = req.restaurant.restaurantId;
    const restaurantOrders = db.orders.filter(order => order.restaurantId === restaurantId);
    
    // Statistiques aujourd'hui
    const today = new Date();
    const todayOrders = restaurantOrders.filter(order => {
      const orderDate = new Date(order.createdAt);
      return orderDate.toDateString() === today.toDateString();
    });

    // Revenus du jour
    const todayRevenue = todayOrders
      .filter(order => order.paymentStatus === 'paid')
      .reduce((sum, order) => sum + order.total, 0);

    // Plats populaires
    const itemCounts = {};
    restaurantOrders.forEach(order => {
      order.items.forEach(item => {
        itemCounts[item.name] = (itemCounts[item.name] || 0) + item.quantity;
      });
    });

    const popularItems = Object.entries(itemCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([name, count]) => ({ name, count }));

    // Temps de préparation moyen
    const completedOrders = restaurantOrders.filter(order => order.actualPrepTime);
    const avgPrepTime = completedOrders.length > 0 
      ? Math.round(completedOrders.reduce((sum, order) => sum + order.actualPrepTime, 0) / completedOrders.length)
      : 0;

    res.json({
      today: {
        orders: todayOrders.length,
        revenue: todayRevenue,
        pending: todayOrders.filter(o => o.status === 'pending').length,
        preparing: todayOrders.filter(o => o.status === 'preparing').length,
        ready: todayOrders.filter(o => o.status === 'ready').length,
        completed: todayOrders.filter(o => o.status === 'completed').length
      },
      total: {
        orders: restaurantOrders.length,
        revenue: restaurantOrders.filter(o => o.paymentStatus === 'paid').reduce((sum, o) => sum + o.total, 0)
      },
      popularItems,
      avgPrepTime
    });
  } catch (error) {
    console.error('❌ Erreur statistiques restaurant:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des statistiques' });
  }
});

// ============================================
// ROUTES COMMUNES
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'CampusEats API is running on Render!',
    timestamp: new Date().toISOString(),
    version: '1.1.0 - HASH CORRIGÉ',
    endpoints: {
      student: ['auth', 'restaurants', 'orders', 'profile'],
      restaurant: ['auth/login', 'orders', 'scan', 'stats']
    },
    debug: {
      restaurantCredentials: [
        'pizzeria@campus.fr / password123',
        'green@campus.fr / password123'
      ]
    }
  });
});

app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route non trouvée' });
});

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`🚀 CampusEats API démarrée sur le port ${PORT}`);
  console.log(`🌐 Prêt à servir les étudiants du campus!`);
  console.log(`🏪 Dashboard restaurant disponible!`);
  console.log(`📊 Comptes restaurant de test:`);
  console.log(`   - pizzeria@campus.fr / password123`);
  console.log(`   - green@campus.fr / password123`);
  
  // Vérification automatique du hash au démarrage
  console.log('\n🔐 === VÉRIFICATION HASH AU DÉMARRAGE ===');
  try {
    const testPassword = 'password123';
    const correctHash = '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi';
    
    const isValid = await bcrypt.compare(testPassword, correctHash);
    console.log(`✅ Test hash pour "${testPassword}": ${isValid ? 'VALIDE' : 'INVALIDE'}`);
    
    // Test avec les restaurants de la DB
    for (const restaurant of db.restaurants) {
      const restaurantTest = await bcrypt.compare(testPassword, restaurant.password);
      console.log(`🏪 ${restaurant.name} (${restaurant.email}): ${restaurantTest ? '✅ OK' : '❌ ERREUR'}`);
    }
  } catch (error) {
    console.error('❌ Erreur vérification hash:', error);
  }
  console.log('🔐 === FIN VÉRIFICATION ===\n');
});

module.exports = app;
