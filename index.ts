import cors from 'cors';
import dotenv from 'dotenv';
import express, { NextFunction, Request, Response } from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';

dotenv.config();

interface AuthPayload {
  id?: string;
  role?: string;
  [key: string]: unknown;
}

interface AuthedRequest extends Request {
  user?: AuthPayload;
}

// Points at your Next.js app's Better Auth JWKS endpoint, e.g. http://localhost:3000/api/auth/jwks
const AUTH_ISSUER_URL = process.env.BETTER_AUTH_URL || 'http://localhost:3000';
const JWKS = createRemoteJWKSet(new URL(`${AUTH_ISSUER_URL}/api/auth/jwks`));

async function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header.' });
  }

  const token = authHeader.slice('Bearer '.length).trim();

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: AUTH_ISSUER_URL,
    });

    const decoded = payload as AuthPayload;

    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required.' });
    }

    req.user = decoded;
    return next();
  } catch (error) {
    console.error('JWT verification failed:', error);
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

interface Product {
  _id?: ObjectId;
  title: string;
  shortDescription: string;
  fullDescription: string;
  price: string;
  date: string;
  priority: 'Low' | 'Medium' | 'High';
  imageUrl: string;
}

const app = express();
app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017';
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const db = client.db('dropsmine_db');
const productsCollection = db.collection<Product>('products');

function serializeProduct(product: Product) {
  return {
    id: product._id?.toString(),
    title: product.title,
    shortDescription: product.shortDescription,
    fullDescription: product.fullDescription,
    price: product.price,
    date: product.date,
    priority: product.priority,
    imageUrl: product.imageUrl,
  };
}

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

app.get('/products', async (_req: Request, res: Response) => {
  try {
    const products = await productsCollection.find({}).sort({ date: -1 }).toArray();
    res.json(products.map(serializeProduct));
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products.' });
  }
});

app.post('/products', requireAdmin, async (req: Request, res: Response) => {
  const {
    title,
    shortDescription,
    fullDescription,
    price,
    date,
    priority,
    imageUrl,
  } = req.body as Partial<Product>;

  if (!title || typeof title !== 'string' || title.trim() === '') {
    return res.status(400).json({ error: 'Title is required.' });
  }

  if (!price || typeof price !== 'string' || price.trim() === '') {
    return res.status(400).json({ error: 'Price is required.' });
  }

  if (priority && !['Low', 'Medium', 'High'].includes(priority)) {
    return res.status(400).json({ error: 'Priority must be Low, Medium, or High.' });
  }

  try {
    const product: Product = {
      title: title.trim(),
      shortDescription: typeof shortDescription === 'string' ? shortDescription.trim() : '',
      fullDescription: typeof fullDescription === 'string' ? fullDescription.trim() : '',
      price: price.trim(),
      date: typeof date === 'string' && date.trim() !== '' ? date.trim() : new Date().toISOString().slice(0, 10),
      priority: (priority as Product['priority']) || 'Medium',
      imageUrl: typeof imageUrl === 'string' ? imageUrl.trim() : '',
    };

    const result = await productsCollection.insertOne(product);
    const createdProduct = await productsCollection.findOne({ _id: result.insertedId });

    return res.status(201).json(createdProduct ? serializeProduct(createdProduct) : product);
  } catch (error) {
    console.error('Error creating product:', error);
    return res.status(500).json({ error: 'Failed to create product.' });
  }
});

app.get('/products/:id', async (req: Request, res: Response) => {
  try {
    const product = await productsCollection.findOne({ _id: new ObjectId(req.params.id) });

    if (!product) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    return res.json(serializeProduct(product));
  } catch (error) {
    console.error('Error fetching product:', error);
    return res.status(400).json({ error: 'Invalid product id.' });
  }
});

app.put('/products/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const updates: Partial<Product> = {};
    const {
      title,
      shortDescription,
      fullDescription,
      price,
      date,
      priority,
      imageUrl,
    } = req.body as Partial<Product>;

    if (title !== undefined) {
      if (typeof title !== 'string' || title.trim() === '') {
        return res.status(400).json({ error: 'Title must be a non-empty string.' });
      }
      updates.title = title.trim();
    }

    if (shortDescription !== undefined) {
      updates.shortDescription = typeof shortDescription === 'string' ? shortDescription.trim() : '';
    }

    if (fullDescription !== undefined) {
      updates.fullDescription = typeof fullDescription === 'string' ? fullDescription.trim() : '';
    }

    if (price !== undefined) {
      if (typeof price !== 'string' || price.trim() === '') {
        return res.status(400).json({ error: 'Price must be a non-empty string.' });
      }
      updates.price = price.trim();
    }

    if (date !== undefined) {
      updates.date = typeof date === 'string' ? date.trim() : '';
    }

    if (priority !== undefined) {
      if (!['Low', 'Medium', 'High'].includes(priority as string)) {
        return res.status(400).json({ error: 'Priority must be Low, Medium, or High.' });
      }
      updates.priority = priority as Product['priority'];
    }

    if (imageUrl !== undefined) {
      updates.imageUrl = typeof imageUrl === 'string' ? imageUrl.trim() : '';
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields provided.' });
    }

    await productsCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    const updatedProduct = await productsCollection.findOne({ _id: new ObjectId(req.params.id) });

    if (!updatedProduct) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    return res.json(serializeProduct(updatedProduct));
  } catch (error) {
    console.error('Error updating product:', error);
    return res.status(400).json({ error: 'Invalid product id.' });
  }
});

app.patch('/products/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const updates: Partial<Product> = {};
    const {
      title,
      shortDescription,
      fullDescription,
      price,
      date,
      priority,
      imageUrl,
    } = req.body as Partial<Product>;

    if (title !== undefined) {
      if (typeof title !== 'string' || title.trim() === '') {
        return res.status(400).json({ error: 'Title must be a non-empty string.' });
      }
      updates.title = title.trim();
    }

    if (shortDescription !== undefined) {
      updates.shortDescription = typeof shortDescription === 'string' ? shortDescription.trim() : '';
    }

    if (fullDescription !== undefined) {
      updates.fullDescription = typeof fullDescription === 'string' ? fullDescription.trim() : '';
    }

    if (price !== undefined) {
      if (typeof price !== 'string' || price.trim() === '') {
        return res.status(400).json({ error: 'Price must be a non-empty string.' });
      }
      updates.price = price.trim();
    }

    if (date !== undefined) {
      updates.date = typeof date === 'string' ? date.trim() : '';
    }

    if (priority !== undefined) {
      if (!['Low', 'Medium', 'High'].includes(priority as string)) {
        return res.status(400).json({ error: 'Priority must be Low, Medium, or High.' });
      }
      updates.priority = priority as Product['priority'];
    }

    if (imageUrl !== undefined) {
      updates.imageUrl = typeof imageUrl === 'string' ? imageUrl.trim() : '';
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields provided.' });
    }

    await productsCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    const updatedProduct = await productsCollection.findOne({ _id: new ObjectId(req.params.id) });

    if (!updatedProduct) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    return res.json(serializeProduct(updatedProduct));
  } catch (error) {
    console.error('Error patching product:', error);
    return res.status(400).json({ error: 'Invalid product id.' });
  }
});

app.delete('/products/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const result = await productsCollection.deleteOne({ _id: new ObjectId(req.params.id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    return res.status(204).send();
  } catch (error) {
    console.error('Error deleting product:', error);
    return res.status(400).json({ error: 'Invalid product id.' });
  }
});

const port = Number(process.env.PORT) || 8000;

async function startServer() {
  try {
    await client.connect();
    console.log('Connected to MongoDB successfully.');
    app.listen(port, () => {
      console.log(`CRUD server running on http://localhost:${port}`);
    });
  } catch (error) {
    console.error('MongoDB connection failed:', error);
    process.exit(1);
  }
}

startServer();