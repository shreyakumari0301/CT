"""
Embedding utility functions for B2F repository using text-embedding-3-large
"""

import os
import json
import pickle
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
import openai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    print("⚠️  Warning: FAISS not available, falling back to basic similarity search")

class EmbeddingManager:
    """Manages text embeddings using OpenAI's text-embedding-3-large model with FAISS indexing"""
    
    def __init__(self, model_name: str = "text-embedding-3-large", cache_dir: str = None):
        """Initialize the embedding manager"""
        self.model_name = model_name
        self.client = self._setup_openai_client()
        
        # Setup cache directory
        if cache_dir is None:
            from config.settings import EMBEDDING_CACHE
            self.cache_dir = Path(EMBEDDING_CACHE)
        else:
            self.cache_dir = Path(cache_dir)
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Model dimensions
        self.dimensions = 3072  # text-embedding-3-large has 3072 dimensions
        
        # FAISS index and cache
        self.faiss_index = None
        self.corpus_data = {}
        self.embeddings_data = {}
        
        print(f"✅ Embedding Manager initialized with {self.model_name} ({self.dimensions} dimensions)")
        if FAISS_AVAILABLE:
            print("✅ FAISS indexing available")
        else:
            print("⚠️  FAISS not available, using basic similarity search")
    
    def _setup_openai_client(self) -> openai.OpenAI:
        """Setup OpenAI client with API key"""
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        try:
            client = openai.OpenAI(api_key=api_key)
            return client
        except Exception as e:
            print(f"❌ Error initializing OpenAI client: {e}")
            raise
    
    def _get_cache_files(self, framework: str) -> Tuple[Path, Path, Path]:
        """Get cache file paths for a specific framework"""
        corpus_file = self.cache_dir / f"{framework}_corpus.pkl"
        embeddings_file = self.cache_dir / f"{framework}_embeddings.pkl"
        index_file = self.cache_dir / f"{framework}_index.faiss"
        return corpus_file, embeddings_file, index_file
    
    def _load_cache(self, framework: str) -> bool:
        """Load cached data for a specific framework"""
        corpus_file, embeddings_file, index_file = self._get_cache_files(framework)
        
        try:
            # Load corpus data
            if corpus_file.exists():
                with open(corpus_file, 'rb') as f:
                    self.corpus_data[framework] = pickle.load(f)
                print(f"✅ Loaded {len(self.corpus_data[framework])} corpus entries from cache")
            else:
                self.corpus_data[framework] = {}
                return False
            
            # Load embeddings data
            if embeddings_file.exists():
                with open(embeddings_file, 'rb') as f:
                    self.embeddings_data[framework] = pickle.load(f)
                print(f"✅ Loaded {len(self.embeddings_data[framework])} embeddings from cache")
            else:
                self.embeddings_data[framework] = {}
                return False
            
            # Load FAISS index
            if FAISS_AVAILABLE and index_file.exists():
                self.faiss_index = faiss.read_index(str(index_file))
                print(f"✅ Loaded FAISS index with {self.faiss_index.ntotal} vectors")
            else:
                self.faiss_index = None
            
            return True
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to load cache for {framework}: {e}")
            return False
    
    def _save_cache(self, framework: str) -> bool:
        """Save cached data for a specific framework"""
        corpus_file, embeddings_file, index_file = self._get_cache_files(framework)
        
        try:
            # Save corpus data
            with open(corpus_file, 'wb') as f:
                pickle.dump(self.corpus_data[framework], f)
            
            # Save embeddings data
            with open(embeddings_file, 'wb') as f:
                pickle.dump(self.embeddings_data[framework], f)
            
            # Save FAISS index
            if FAISS_AVAILABLE and self.faiss_index is not None:
                faiss.write_index(self.faiss_index, str(index_file))
            
            print(f"✅ Saved cache for {framework} framework")
            return True
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to save cache for {framework}: {e}")
            return False
    
    def precompute_corpus_embeddings(self, corpus_entries: List[Dict[str, Any]], framework: str, text_field: str = "description") -> bool:
        """Pre-compute embeddings for all corpus entries and create FAISS index"""
        print(f"🚀 Pre-computing embeddings for {len(corpus_entries)} {framework.upper()} corpus entries...")
        
        # Check if already cached
        if self._load_cache(framework):
            print(f"✅ {framework.upper()} corpus already cached")
            return True
        
        # Initialize data structures
        self.corpus_data[framework] = {}
        self.embeddings_data[framework] = {}
        
        # Process corpus entries
        embeddings_list = []
        valid_entries = []
        
        for i, entry in enumerate(corpus_entries):
            entry_id = entry.get('id', str(i))
            text = entry.get(text_field, "")
            
            # Ensure text is a string (handle cases where it might be dict or other types)
            if isinstance(text, dict):
                # Try to extract a string representation
                text = json.dumps(text) if text else ""
            elif not isinstance(text, str):
                text = str(text) if text else ""
            
            if not text or not text.strip():
                continue
            
            # Store corpus entry
            self.corpus_data[framework][entry_id] = entry
            
            # Compute embedding
            embedding = self.get_embedding(text, use_cache=False)  # Don't use text-level cache here
            if embedding is not None:
                self.embeddings_data[framework][entry_id] = embedding
                embeddings_list.append(embedding)
                valid_entries.append(entry_id)
            
            if (i + 1) % 50 == 0:
                print(f"  Processed {i + 1}/{len(corpus_entries)} entries...")
        
        # Create FAISS index if available
        if FAISS_AVAILABLE and embeddings_list:
            try:
                # Convert to numpy array
                embeddings_array = np.array(embeddings_list, dtype=np.float32)
                
                # Create FAISS index
                self.faiss_index = faiss.IndexFlatIP(self.dimensions)  # Inner product for cosine similarity
                
                # Normalize embeddings for cosine similarity
                faiss.normalize_L2(embeddings_array)
                
                # Add vectors to index
                self.faiss_index.add(embeddings_array)
                
                print(f"✅ Created FAISS index with {self.faiss_index.ntotal} vectors")
                
            except Exception as e:
                print(f"⚠️  Warning: Failed to create FAISS index: {e}")
                self.faiss_index = None
        
        # Save cache
        success = self._save_cache(framework)
        
        if success:
            print(f"✅ Pre-computed {len(valid_entries)} embeddings for {framework.upper()} corpus")
        else:
            print(f"❌ Failed to save cache for {framework.upper()}")
        
        return success
    
    def get_embedding(self, text: str, use_cache: bool = True) -> Optional[np.ndarray]:
        """Get embedding for text using OpenAI API"""
        if not text or not text.strip():
            return None
        
        try:
            # Truncate text if needed (text-embedding-3-large has 8192 token limit)
            # Conservative limit: ~6000 characters
            if len(text) > 6000:
                text = text[:6000]
            
            response = self.client.embeddings.create(
                model=self.model_name,
                input=text
            )
            
            embedding = np.array(response.data[0].embedding, dtype=np.float32)
            return embedding
            
        except Exception as e:
            print(f"❌ Error getting embedding: {e}")
            return None
    
    def find_similar_entries(
        self, 
        query_text: str, 
        framework: str,
        top_k: int = 10,
        similarity_threshold: float = 0.5
    ) -> List[Dict[str, Any]]:
        """Find similar entries using FAISS index or fallback to basic search"""
        print(f"🔍 Finding similar entries for query (top {top_k})...")
        
        # Check if cache is loaded
        if framework not in self.corpus_data or framework not in self.embeddings_data:
            if not self._load_cache(framework):
                print(f"❌ Failed to load cache for {framework}")
                return []
        
        # Get query embedding
        query_embedding = self.get_embedding(query_text)
        if query_embedding is None:
            print("❌ Failed to get query embedding")
            return []
        
        # Use FAISS index if available
        if FAISS_AVAILABLE and self.faiss_index is not None:
            return self._search_with_faiss(query_embedding, framework, top_k, similarity_threshold)
        else:
            return self._search_with_basic(query_embedding, framework, top_k, similarity_threshold)
    
    def _search_with_faiss(self, query_embedding: np.ndarray, framework: str, top_k: int, similarity_threshold: float) -> List[Dict[str, Any]]:
        """Search using FAISS index"""
        try:
            # Normalize query embedding
            query_normalized = query_embedding.reshape(1, -1).astype(np.float32)
            faiss.normalize_L2(query_normalized)
            
            # Search
            similarities, indices = self.faiss_index.search(query_normalized, top_k)
            
            # Debug: Print raw FAISS similarity scores
            if len(similarities[0]) > 0:
                raw_scores = [float(s) for s in similarities[0][:5]]
                print(f"      🔍 FAISS raw similarity scores (top 5): {raw_scores}")
            
            # Process results
            results = []
            for i, (similarity, idx) in enumerate(zip(similarities[0], indices[0])):
                if idx < 0:
                    continue
                if similarity < similarity_threshold:
                    if i < 3:  # Debug: Print first few filtered out scores
                        print(f"      ⚠️  Candidate {i+1} filtered: similarity={float(similarity):.4f} < threshold={similarity_threshold}")
                    continue
                
                # Get entry ID from index
                entry_ids = list(self.corpus_data[framework].keys())
                if idx < len(entry_ids):
                    entry_id = entry_ids[idx]
                    entry = self.corpus_data[framework][entry_id]
                    
                    results.append({
                        'id': entry_id,
                        'name': entry.get('name', entry.get('title', '')),
                        'description': entry.get('description', entry.get('contents', '')),
                        'similarity': float(similarity),
                        'original_entry': entry
                    })
            
            print(f"✅ Found {len(results)} similar entries above threshold {similarity_threshold}")
            return results
            
        except Exception as e:
            print(f"⚠️  Warning: FAISS search failed, falling back to basic search: {e}")
            return self._search_with_basic(query_embedding, framework, top_k, similarity_threshold)
    
    def _search_with_basic(self, query_embedding: np.ndarray, framework: str, top_k: int, similarity_threshold: float) -> List[Dict[str, Any]]:
        """Fallback to basic similarity search"""
        similarities = []
        
        for entry_id, embedding in self.embeddings_data[framework].items():
            similarity = self.compute_similarity(query_embedding, embedding)
            
            if similarity >= similarity_threshold:
                entry = self.corpus_data[framework][entry_id]
                similarities.append({
                    'entry': entry,
                    'similarity': similarity
                })
        
        # Sort by similarity and return top_k
        similarities.sort(key=lambda x: x['similarity'], reverse=True)
        top_results = similarities[:top_k]
        
        print(f"✅ Found {len(top_results)} similar entries above threshold {similarity_threshold}")
        
        return [
            {
                'id': result['entry'].get('id', ''),
                'name': result['entry'].get('name', result['entry'].get('title', '')),
                'description': result['entry'].get('description', result['entry'].get('contents', '')),
                'similarity': result['similarity'],
                'original_entry': result['entry']
            }
            for result in top_results
        ]
    
    def compute_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """Compute cosine similarity between two embeddings"""
        if embedding1 is None or embedding2 is None:
            return 0.0
        
        # Normalize embeddings
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        # Compute cosine similarity
        similarity = np.dot(embedding1, embedding2) / (norm1 * norm2)
        return float(similarity)
    
    def clear_cache(self, framework: str = None):
        """Clear cache for specific framework or all frameworks"""
        if framework:
            # Clear specific framework
            corpus_file, embeddings_file, index_file = self._get_cache_files(framework)
            for file_path in [corpus_file, embeddings_file, index_file]:
                if file_path.exists():
                    file_path.unlink()
            
            if framework in self.corpus_data:
                del self.corpus_data[framework]
            if framework in self.embeddings_data:
                del self.embeddings_data[framework]
            
            print(f"✅ Cleared cache for {framework}")
        else:
            # Clear all frameworks
            for file_path in self.cache_dir.glob("*"):
                if file_path.is_file():
                    file_path.unlink()
            
            self.corpus_data.clear()
            self.embeddings_data.clear()
            self.faiss_index = None
            
            print("✅ Cleared all cache")

def create_embedding_manager(model_name: str = None) -> EmbeddingManager:
    """Create an embedding manager instance"""
    if model_name is None:
        from config.settings import EMBEDDING_MODEL
        model_name = EMBEDDING_MODEL
    
    return EmbeddingManager(model_name=model_name)
