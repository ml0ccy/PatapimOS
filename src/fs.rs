use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub file_type: FileType,
    pub size: usize,
    pub created: u64,
    pub modified: u64,
    pub permissions: u32,
}

impl FileMetadata {
    pub fn new_file() -> Self {
        let now = 0;
        FileMetadata {
            file_type: FileType::File,
            size: 0,
            created: now,
            modified: now,
            permissions: 0o644,
        }
    }

    pub fn new_directory() -> Self {
        let now = 0;
        FileMetadata {
            file_type: FileType::Directory,
            size: 0,
            created: now,
            modified: now,
            permissions: 0o755,
        }
    }
}

#[derive(Debug, Clone)]
pub struct INode {
    pub name: String,
    pub metadata: FileMetadata,
    pub content: Vec<u8>,
    pub children: BTreeMap<String, INode>,
}

impl INode {
    pub fn new_file(name: String, content: Vec<u8>) -> Self {
        let mut metadata = FileMetadata::new_file();
        metadata.size = content.len();

        INode {
            name,
            metadata,
            content,
            children: BTreeMap::new(),
        }
    }

    pub fn new_directory(name: String) -> Self {
        INode {
            name,
            metadata: FileMetadata::new_directory(),
            content: Vec::new(),
            children: BTreeMap::new(),
        }
    }

    pub fn is_directory(&self) -> bool {
        self.metadata.file_type == FileType::Directory
    }

    pub fn is_file(&self) -> bool {
        self.metadata.file_type == FileType::File
    }
}

pub struct RamDisk {
    root: INode,
    total_size: usize,
    max_size: usize,
    file_count: usize,
}

impl RamDisk {
    pub const fn new() -> Self {
        RamDisk {
            root: INode {
                name: String::new(),
                metadata: FileMetadata {
                    file_type: FileType::Directory,
                    size: 0,
                    created: 0,
                    modified: 0,
                    permissions: 0o755,
                },
                content: Vec::new(),
                children: BTreeMap::new(),
            },
            total_size: 0,
            max_size: 512 * 1024,
            file_count: 0,
        }
    }

    fn parse_path(path: &str) -> Vec<&str> {
        path.split('/').filter(|s| !s.is_empty()).collect()
    }

    fn get_node_mut(&mut self, path: &str) -> Option<&mut INode> {
        let parts = Self::parse_path(path);

        if parts.is_empty() {
            return Some(&mut self.root);
        }

        let mut current = &mut self.root;

        for part in parts {
            current = current.children.get_mut(part)?;
            if !current.is_directory() {
                return None;
            }
        }

        Some(current)
    }

    fn get_node(&self, path: &str) -> Option<&INode> {
        let parts = Self::parse_path(path);

        if parts.is_empty() {
            return Some(&self.root);
        }

        let mut current = &self.root;

        for part in parts {
            current = current.children.get(part)?;
            if !current.is_directory() {
                return None;
            }
        }

        Some(current)
    }

    pub fn mkdir(&mut self, path: &str) -> Result<(), &'static str> {
        if path.is_empty() || path == "/" {
            return Err("Invalid path");
        }

        let parts = Self::parse_path(path);
        if parts.is_empty() {
            return Err("Invalid path");
        }

        let dir_name = parts[parts.len() - 1];
        let parent_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        let parent = self
            .get_node_mut(&parent_path)
            .ok_or("Parent directory not found")?;

        if parent.children.contains_key(dir_name) {
            return Err("Directory already exists");
        }

        parent.children.insert(
            dir_name.to_string(),
            INode::new_directory(dir_name.to_string()),
        );
        Ok(())
    }

    pub fn create_file(&mut self, path: &str, content: Vec<u8>) -> Result<(), &'static str> {
        if path.is_empty() || path == "/" {
            return Err("Invalid path");
        }

        let parts = Self::parse_path(path);
        if parts.is_empty() {
            return Err("Invalid path");
        }

        let size = content.len();

        if self.total_size + size > self.max_size {
            return Err("Insufficient disk space");
        }

        let file_name = parts[parts.len() - 1];
        let parent_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        let parent = self
            .get_node_mut(&parent_path)
            .ok_or("Parent directory not found")?;

        if parent.children.contains_key(file_name) {
            return Err("File already exists");
        }

        parent.children.insert(
            file_name.to_string(),
            INode::new_file(file_name.to_string(), content),
        );
        self.total_size += size;
        self.file_count += 1;

        Ok(())
    }

    pub fn write_file(&mut self, path: &str, content: Vec<u8>) -> Result<(), &'static str> {
        if path.is_empty() || path == "/" {
            return Err("Invalid path");
        }

        let parts = Self::parse_path(path);
        if parts.is_empty() {
            return Err("Invalid path");
        }

        let file_name = parts[parts.len() - 1].to_string();
        let parent_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        // Сначала проверяем размер и получаем старый размер
        let old_size = {
            let parent = self
                .get_node(&parent_path)
                .ok_or("Parent directory not found")?;

            if let Some(file_node) = parent.children.get(&file_name) {
                if !file_node.is_file() {
                    return Err("Not a file");
                }

                let old_size = file_node.content.len();
                let new_size = content.len();

                if self.total_size - old_size + new_size > self.max_size {
                    return Err("Insufficient disk space");
                }

                old_size
            } else {
                return Err("File not found");
            }
        }; // parent освобождается здесь

        // Теперь можем спокойно менять self
        let new_size = content.len();
        self.total_size -= old_size;
        self.total_size += new_size;

        let parent = self
            .get_node_mut(&parent_path)
            .ok_or("Parent directory not found")?;

        if let Some(file_node) = parent.children.get_mut(&file_name) {
            file_node.content = content;
            Ok(())
        } else {
            Err("File not found")
        }
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, &'static str> {
        let parts = Self::parse_path(path);
        if parts.is_empty() {
            return Err("Invalid path");
        }

        let file_name = parts[parts.len() - 1];
        let parent_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        let parent = self
            .get_node(&parent_path)
            .ok_or("Parent directory not found")?;

        if let Some(file_node) = parent.children.get(file_name) {
            if !file_node.is_file() {
                return Err("Not a file");
            }
            Ok(file_node.content.clone())
        } else {
            Err("File not found")
        }
    }

    pub fn delete_file(&mut self, path: &str) -> Result<(), &'static str> {
        if path.is_empty() || path == "/" {
            return Err("Invalid path");
        }

        let parts = Self::parse_path(path);
        if parts.is_empty() {
            return Err("Invalid path");
        }

        let file_name = parts[parts.len() - 1];
        let parent_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        let parent = self
            .get_node_mut(&parent_path)
            .ok_or("Parent directory not found")?;

        if let Some(node) = parent.children.remove(file_name) {
            self.total_size -= node.metadata.size;
            if node.is_file() {
                self.file_count -= 1;
            }
            Ok(())
        } else {
            Err("File not found")
        }
    }

    pub fn delete_directory(&mut self, path: &str) -> Result<(), &'static str> {
        if path.is_empty() || path == "/" {
            return Err("Invalid path");
        }

        let parts = Self::parse_path(path);
        if parts.is_empty() {
            return Err("Invalid path");
        }

        let dir_name = parts[parts.len() - 1];
        let parent_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        let parent = self
            .get_node_mut(&parent_path)
            .ok_or("Parent directory not found")?;

        if let Some(node) = parent.children.get(dir_name) {
            if !node.is_directory() {
                return Err("Not a directory");
            }
            if !node.children.is_empty() {
                return Err("Directory not empty");
            }
        }

        parent.children.remove(dir_name);
        Ok(())
    }

    pub fn list_directory(
        &self,
        path: &str,
    ) -> Result<Vec<(String, FileType, usize)>, &'static str> {
        let node = self.get_node(path).ok_or("Directory not found")?;

        if !node.is_directory() {
            return Err("Not a directory");
        }

        Ok(node
            .children
            .iter()
            .map(|(name, node)| (name.clone(), node.metadata.file_type, node.metadata.size))
            .collect())
    }

    pub fn file_exists(&self, path: &str) -> bool {
        let parts = Self::parse_path(path);
        if parts.is_empty() {
            return false;
        }

        let file_name = parts[parts.len() - 1];
        let parent_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        if let Some(parent) = self.get_node(&parent_path) {
            parent
                .children
                .get(file_name)
                .map_or(false, |n| n.is_file())
        } else {
            false
        }
    }

    pub fn get_file_size(&self, path: &str) -> Result<usize, &'static str> {
        let parts = Self::parse_path(path);
        if parts.is_empty() {
            return Err("Invalid path");
        }

        let file_name = parts[parts.len() - 1];
        let parent_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        if let Some(parent) = self.get_node(&parent_path) {
            if let Some(node) = parent.children.get(file_name) {
                if !node.is_file() {
                    return Err("Not a file");
                }
                return Ok(node.metadata.size);
            }
        }

        Err("File not found")
    }

    pub fn get_total_size(&self) -> usize {
        self.total_size
    }

    pub fn get_free_space(&self) -> usize {
        self.max_size - self.total_size
    }

    pub fn get_file_count(&self) -> usize {
        self.file_count
    }

    pub fn get_tree(&self) -> String {
        self.tree_impl(&self.root, 0)
    }

    fn tree_impl(&self, node: &INode, indent: usize) -> String {
        let mut result = String::new();
        let prefix = " ".repeat(indent);

        for (name, child) in &node.children {
            let type_str = if child.is_directory() {
                "[DIR]"
            } else {
                "[FILE]"
            };
            result.push_str(&alloc::format!(
                "{}├─ {} {} ({}B)\n",
                prefix,
                type_str,
                name,
                child.metadata.size
            ));

            if child.is_directory() {
                result.push_str(&self.tree_impl(child, indent + 2));
            }
        }

        result
    }
}

lazy_static! {
    pub static ref RAMDISK: Mutex<RamDisk> = Mutex::new(RamDisk::new());
}
