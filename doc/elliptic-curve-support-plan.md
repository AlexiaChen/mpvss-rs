# PVSS 椭圆曲线支持实现计划

## 目标

将 mpvss-rs 库重构为支持多种密码学群（MODP 和椭圆曲线）的统一接口，优先实现 secp256k1，版本升级至 1.0.0。

## 用户确认的设计决策

1. **曲线选择**: 先实现 secp256k1（素阶群，余因子 h=1）
2. **兼容性**: 完全泛型重构，不保留旧 API，升级至 1.0.0
3. **抽象方法**: 统一使用 `exp()` 方法（MODP 为模幂，EC 为标量乘法）

## 背景分析

### secp256k1 群性质
- **阶数 n**: `FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141`（素数）
- **余因子 h**: 1（确认是素阶群）
- **曲线方程**: y² = x³ + 7
- **基点 G**: 已标准化定义

### 当前代码结构

| 文件 | 作用 | 需要修改 |
|------|------|----------|
| `src/mpvss.rs` | MODP 群参数 + 核心操作 | 重构为 ModpGroup |
| `src/participant.rs` | 用户 API | 泛型化 |
| `src/dleq.rs` | DLEQ 零知识证明 | 泛型化 |
| `src/polynomial.rs` | Shamir 多项式 | 保持不变（操作标量） |
| `src/sharebox.rs` | 份额数据结构 | 泛型化 |
| `src/util.rs` | 工具函数 | 保持不变 |

### 关键群操作映射

| 操作 | MODP (乘法群) | secp256k1 (加法群) |
|------|--------------|------------------|
| 群元素类型 | `BigInt` | `AffinePoint` |
| 标量类型 | `BigInt` | `Scalar` |
| 生成元 | `G = 2` | `AffinePoint::GENERATOR` |
| 群阶 | `q` (安全素数) | `n` (曲线阶) |
| 子群阶 | `g = (q-1)/2` | `n` (余因子=1) |
| exp(G, k) | `G^k mod q` | `k * G` (标量乘法) |
| mul(A, B) | `A * B mod q` | `A + B` (点加) |
| 逆元 | `a^(-1) mod q` | `a.invert()` |
| 单位元 | `1` | `Identity` (无穷远点) |

**重要说明**：
- **MODP 使用乘法群**：群运算是模乘法 `a * b mod q`
- **椭圆曲线使用加法群**：群运算是点加法 `A + B`
- **mul(A, B) 的用途**：
  1. DLEQ 验证：`a1 = g^response * h^challenge`（MODP）或 `response*g + challenge*h`（EC）
  2. 秘密重构：`G^s = ∏ S_i^λ_i`，将所有 Lagrange 因子乘在一起

## 实现计划

### 第一阶段：创建新分支和依赖更新

```bash
git checkout -b feature/secp256k1-support
```

**修改 `Cargo.toml`**:
```toml
[package]
version = "1.0.0-alpha.1"
edition = "2021"

[dependencies]
num-bigint = { version = "0.2", features = ["rand"] }
num-integer = "0.1"
num-primes = "0.3"
num-traits = "0.2"
rand = "0.5"
rayon = "1.11"
sha2 = "0.10"

# 新增椭圆曲线支持
k256 = { version = "0.13", features = ["arithmetic", "expose-field"], optional = true }

[features]
default = []
secp256k1 = ["k256"]
```

### 第二阶段：定义核心 Trait

**新建 `src/group.rs`**:
```rust
use sha2::{Digest, Sha256};

/// 密码学群抽象
pub trait Group: Clone + Send + Sync {
    /// 标量类型（私钥/指数）
    type Scalar: Clone + Eq + std::fmt::Debug + Send + Sync;

    /// 群元素类型（公钥/点）
    type Element: Clone + Eq + std::fmt::Debug + Send + Sync;

    /// 群阶（MODP 为 q-1，EC 为曲线阶 n）
    fn order(&self) -> &Self::Scalar;

    /// 子群阶（MODP 为 g=(q-1)/2，EC 为 n）
    fn subgroup_order(&self) -> &Self::Scalar;

    /// 主生成元 G（用于承诺和公钥生成）
    fn generator(&self) -> Self::Element;

    /// 子群生成元 g（用于计算承诺 C_j = g^a_j）
    fn subgroup_generator(&self) -> Self::Element;

    /// 单位元（MODP 为 1，EC 为无穷远点）
    fn identity(&self) -> Self::Element;

    /// 群操作：exp(G, k) 或 k*G
    fn exp(&self, base: &Self::Element, scalar: &Self::Scalar) -> Self::Element;

    /// 群乘法：A * B（MODP）或 A + B（EC）
    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element;

    /// 标量逆元（用于解密和 Lagrange 插值）
    fn scalar_inverse(&self, x: &Self::Scalar) -> Option<Self::Scalar>;

    /// 元素逆元（用于 Lagrange 插值中的负系数）
    fn element_inverse(&self, x: &Self::Element) -> Option<Self::Element>;

    /// Hash 到标量（用于 DLEQ challenge）
    fn hash_to_scalar(&self, data: &[u8]) -> Self::Scalar;

    /// 元素序列化为字节
    fn element_to_bytes(&self, elem: &Self::Element) -> Vec<u8>;

    /// 字节反序列化为元素
    fn bytes_to_element(&self, bytes: &[u8]) -> Option<Self::Element>;

    /// 标量序列化为字节
    fn scalar_to_bytes(&self, scalar: &Self::Scalar) -> Vec<u8>;

    /// 生成私钥（与群阶互质的随机标量）
    fn generate_private_key(&self) -> Self::Scalar;

    /// 从私钥生成公钥：P = G^k 或 k*G
    fn generate_public_key(&self, private_key: &Self::Scalar) -> Self::Element;
}
```

### 第三阶段：实现 ModpGroup

**新建 `src/groups/mod.rs` 和 `src/groups/modp.rs`**:

```rust
// src/groups/modp.rs
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::identities::{One, Zero};
use rand::Rng;
use std::sync::Arc;
use sha2::{Digest, Sha256};

use crate::group::Group;

#[derive(Debug, Clone)]
pub struct ModpGroup {
    q: BigInt,           // 安全素数（群模数）
    g: BigInt,           // Sophie Germain 素数（子群阶）
    G: BigInt,           // 主生成元（值为 2）
    q_minus_1: BigInt,   // q - 1 缓存
}

impl ModpGroup {
    pub fn new() -> Arc<Self> {
        // RFC 3526 2048-bit MODP group
        let q: BigUint = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa2...", 16).unwrap();
        let g: BigUint = (q.clone() - BigUint::one()) / BigUint::from(2_u64);
        Arc::new(ModpGroup {
            q: q.to_bigint().unwrap(),
            g: g.to_bigint().unwrap(),
            G: BigInt::from(2),
            q_minus_1: q.to_bigint().unwrap() - BigInt::one(),
        })
    }
}

impl Group for ModpGroup {
    type Scalar = BigInt;
    type Element = BigInt;

    fn order(&self) -> &Self::Scalar {
        &self.q_minus_1
    }

    fn subgroup_order(&self) -> &Self::Scalar {
        &self.g
    }

    fn generator(&self) -> Self::Element {
        self.G.clone()
    }

    fn subgroup_generator(&self) -> Self::Element {
        self.g.clone()
    }

    fn identity(&self) -> Self::Element {
        BigInt::one()
    }

    fn exp(&self, base: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        base.modpow(scalar, &self.q)
    }

    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        (a * b) % &self.q
    }

    fn scalar_inverse(&self, x: &Self::Scalar) -> Option<Self::Scalar> {
        crate::util::Util::mod_inverse(x, &self.q_minus_1)
    }

    fn element_inverse(&self, x: &Self::Element) -> Option<Self::Element> {
        crate::util::Util::mod_inverse(x, &self.q)
    }

    fn hash_to_scalar(&self, data: &[u8]) -> Self::Scalar {
        let hash = Sha256::digest(data);
        BigUint::from_bytes_be(&hash[..])
            .mod_floor(&self.g.to_biguint().unwrap())
            .to_bigint()
            .unwrap()
    }

    fn element_to_bytes(&self, elem: &Self::Element) -> Vec<u8> {
        elem.to_biguint().unwrap().to_bytes_be()
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Option<Self::Element> {
        Some(BigUint::from_bytes_be(bytes).to_bigint().unwrap())
    }

    fn scalar_to_bytes(&self, scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_biguint().unwrap().to_bytes_be()
    }

    fn generate_private_key(&self) -> Self::Scalar {
        let mut rng = rand::thread_rng();
        loop {
            let privkey: BigInt = rng.gen_biguint_below(&self.q.to_biguint().unwrap()).to_bigint().unwrap();
            if privkey.gcd(&self.q_minus_1) == BigInt::one() {
                return privkey;
            }
        }
    }

    fn generate_public_key(&self, private_key: &Self::Scalar) -> Self::Element {
        self.exp(&self.G, private_key)
    }
}
```

### 第四阶段：实现 Secp256k1Group

**新建 `src/groups/secp256k1.rs`**:

```rust
use k256::{Scalar, AffinePoint, ProjectivePoint, SEC1_ENCODED_POINT_SIZE};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::group::Group;

#[derive(Debug, Clone)]
pub struct Secp256k1Group;

impl Secp256k1Group {
    pub fn new() -> Arc<Self> {
        Arc::new(Secp256k1Group)
    }
}

impl Group for Secp256k1Group {
    type Scalar = Scalar;
    type Element = AffinePoint;

    fn order(&self) -> &Self::Scalar {
        // 返回曲线阶 n（k256 内部定义）
        &k256::Secp256k1::ORDER
    }

    fn subgroup_order(&self) -> &Self::Scalar {
        // secp256k1 余因子为 1，群阶 = 子群阶
        &k256::Secp256k1::ORDER
    }

    fn generator(&self) -> Self::Element {
        AffinePoint::GENERATOR
    }

    fn subgroup_generator(&self) -> Self::Element {
        // 对于素阶群，主生成元和子群生成元相同
        AffinePoint::GENERATOR
    }

    fn identity(&self) -> Self::Element {
        AffinePoint::IDENTITY
    }

    fn exp(&self, base: &Self::Element, scalar: &Self::Scalar) -> Self::Element {
        // 标量乘法：scalar * base
        (ProjectivePoint::from(*base) * scalar).into()
    }

    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        // 点加法：a + b
        (ProjectivePoint::from(*a) + ProjectivePoint::from(*b)).into()
    }

    fn scalar_inverse(&self, x: &Self::Scalar) -> Option<Self::Scalar> {
        x.invert().into()
    }

    fn element_inverse(&self, x: &Self::Element) -> Self::Element {
        // 点的负元（用于处理 Lagrange 负系数）
        -ProjectivePoint::from(*x)
    }

    fn hash_to_scalar(&self, data: &[u8]) -> Self::Scalar {
        let hash = Sha256::digest(data);
        Scalar::from_bytes_reduced(&hash)
    }

    fn element_to_bytes(&self, elem: &Self::Element) -> Vec<u8> {
        elem.to_sec1_bytes().to_vec()
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Option<Self::Element> {
        AffinePoint::from_sec1_bytes(bytes).ok()
    }

    fn scalar_to_bytes(&self, scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }

    fn generate_private_key(&self) -> Self::Scalar {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Scalar::from_bytes_reduced(&bytes)
    }

    fn generate_public_key(&self, private_key: &Self::Scalar) -> Self::Element {
        (AffinePoint::GENERATOR * private_key).into()
    }
}
```

### 第五阶段：泛型化数据结构

**修改 `src/sharebox.rs`**:
```rust
use std::collections::BTreeMap;
use std::sync::Arc;
use crate::group::Group;

#[derive(Debug, Clone)]
pub struct ShareBox<G: Group> {
    pub publickey: G::Element,
    pub share: G::Element,
    pub challenge: G::Scalar,
    pub response: G::Scalar,
}

#[derive(Debug, Clone)]
pub struct DistributionSharesBox<G: Group> {
    pub commitments: Vec<G::Element>,
    pub positions: BTreeMap<G::Element, i64>,
    pub shares: BTreeMap<G::Element, G::Element>,
    pub publickeys: Vec<G::Element>,
    pub challenge: G::Scalar,
    pub responses: BTreeMap<G::Element, G::Scalar>,
    pub U: Vec<u8>,  // 改为字节串，支持跨群
}
```

### 第六阶段：泛型化 Participant

**修改 `src/participant.rs`**:
```rust
use std::sync::Arc;
use crate::group::Group;
use crate::groups::{ModpGroup, Secp256k1Group};
use crate::polynomial::Polynomial;
use crate::sharebox::{ShareBox, DistributionSharesBox};

#[derive(Debug, Clone)]
pub struct Participant<G: Group> {
    group: Arc<G>,
    pub privatekey: G::Scalar,
    pub publickey: G::Element,
}

impl<G: Group> Participant<G> {
    pub fn new(group: Arc<G>) -> Self {
        let privatekey = group.generate_private_key();
        let publickey = group.generate_public_key(&privatekey);
        Participant { group, privatekey, publickey }
    }

    // distribute_secret, extract_secret_share, verify_share, reconstruct 等
    // 方法实现，使用 trait 方法替代直接的 BigInt 操作
}
```

### 第七阶段：泛型化 DLEQ

**修改 `src/dleq.rs`**:
```rust
use crate::group::Group;
use sha2::{Digest, Sha256};

pub struct DLEQProof<G: Group> {
    pub a1: G::Element,
    pub a2: G::Element,
    pub challenge: G::Scalar,
    pub response: G::Scalar,
}

impl<G: Group> DLEQProof<G> {
    /// 生成 DLEQ 证明：证明 log_g1(h1) = log_g2(h2) = alpha
    pub fn generate(
        group: &G,
        g1: &G::Element,
        h1: &G::Element,
        g2: &G::Element,
        h2: &G::Element,
        alpha: &G::Scalar,
    ) -> Self {
        // 生成随机 witness w
        let w = group.generate_private_key();

        // 计算 a1 = g1^w, a2 = g2^w
        let a1 = group.exp(g1, &w);
        let a2 = group.exp(g2, &w);

        // 计算 challenge = H(g1, h1, g2, h2, a1, a2)
        let mut hasher = Sha256::new();
        hasher.update(&group.element_to_bytes(g1));
        hasher.update(&group.element_to_bytes(h1));
        hasher.update(&group.element_to_bytes(g2));
        hasher.update(&group.element_to_bytes(h2));
        hasher.update(&group.element_to_bytes(&a1));
        hasher.update(&group.element_to_bytes(&a2));
        let challenge = group.hash_to_scalar(&hasher.finalize());

        // 计算 response = w - alpha * challenge
        // 需要：response = w - alpha*challenge (mod order)
        let alpha_challenge = mul_scalars(alpha, &challenge, group.order());
        let response = sub_scalars(&w, &alpha_challenge, group.order());

        DLEQProof { a1, a2, challenge, response }
    }

    /// 验证 DLEQ 证明
    pub fn verify(&self, group: &G, g1: &G::Element, h1: &G::Element, g2: &G::Element, h2: &G::Element) -> bool {
        // 计算 a1' = g1^response * h1^challenge
        let a1_prime = group.mul(
            &group.exp(g1, &self.response),
            &group.exp(h1, &self.challenge)
        );

        // 计算 a2' = g2^response * h2^challenge
        let a2_prime = group.mul(
            &group.exp(g2, &self.response),
            &group.exp(h2, &self.challenge)
        );

        // 检查 a1' == a1 且 a2' == a2
        a1_prime == self.a1 && a2_prime == self.a2
    }
}

// 辅助函数：标量乘法和减法（需要为每种标量类型实现）
fn mul_scalars<G: Group>(a: &G::Scalar, b: &G::Scalar, order: &G::Scalar) -> G::Scalar {
    // 实现标量乘法模群阶
    // 对于 BigInt: (a * b) % order
    // 对于 Scalar: a * b（k256 内部处理模运算）
}

fn sub_scalars<G: Group>(a: &G::Scalar, b: &G::Scalar, order: &G::Scalar) -> G::Scalar {
    // 实现标量减法模群阶
}
```

### 第八阶段：更新库入口

**修改 `src/lib.rs`**:
```rust
mod group;
mod polynomial;
mod util;
mod sharebox;
mod dleq;

pub mod groups {
    pub mod modp;
    #[cfg(feature = "secp256k1")]
    pub mod secp256k1;
}

use std::sync::Arc;
use group::Group;
use sharebox::{ShareBox, DistributionSharesBox};

/// 使用 MODP 群的参与者（默认类型别名）
pub type Participant = participant::Participant<groups::modp::ModpGroup>;

mod participant {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Participant<G: Group> {
        group: Arc<G>,
        pub privatekey: G::Scalar,
        pub publickey: G::Element,
    }

    impl<G: Group> Participant<G> {
        pub fn new(group: Arc<G>) -> Self { ... }
        // ... 所有方法实现
    }
}

// 导出公共 API
pub use participant::Participant;
pub use sharebox::{ShareBox, DistributionSharesBox};
pub use group::Group;
pub use groups::{ModpGroup, Secp256k1Group};

// 保持兼容的辅助函数
pub use util::Util::{string_to_secret, string_from_secret};
```

### 第九阶段：处理 EC 特殊情况

**问题**: `U = secret ⊕ H(G^s)` 在 EC 中如何处理？

**解决方案**:
- 对于 MODP：`H(G^s)` 直接哈希 BigInt
- 对于 EC：提取 G^s 点的 x 坐标，然后哈希

```rust
// 在 Participant<G> 中
fn encode_secret(&self, secret: &[u8], g_s: &G::Element) -> Vec<u8> {
    // 将 G^s 转换为字节
    let g_s_bytes = self.group.element_to_bytes(g_s);

    // 哈希
    let hash = Sha256::digest(&g_s_bytes);

    // XOR（secret 和 hash 长度处理）
    let mut result = Vec::with_capacity(secret.len().max(hash.len()));
    for i in 0..secret.len().max(hash.len()) {
        let s = secret.get(i).copied().unwrap_or(0);
        let h = hash.get(i).copied().unwrap_or(0);
        result.push(s ^ h);
    }
    result
}
```

### 第十阶段：测试和示例

**新建 `examples/mpvss_all_modp.rs`**:
```rust
use mpvss_rs::{ModpGroup, Participant};
use std::sync::Arc;

fn main() {
    let group = Arc::new(ModpGroup::new());
    let mut dealer = Participant::new(group.clone());
    // ... 现有示例代码
}
```

**新建 `examples/mpvss_all_secp256k1.rs`**:
```rust
use mpvss_rs::{Secp256k1Group, Participant};
use std::sync::Arc;

fn main() {
    let group = Arc::new(Secp256k1Group::new());
    let mut dealer = Participant::new(group.clone());
    // ... 相同的流程，不同的群
}
```

## 关键文件清单

### 新建文件
- `src/group.rs` - Group trait 定义
- `src/groups/mod.rs` - 群实现模块
- `src/groups/modp.rs` - MODP 群实现
- `src/groups/secp256k1.rs` - secp256k1 群实现
- `examples/mpvss_all_secp256k1.rs` - EC 示例

### 修改文件
- `src/lib.rs` - 库入口和类型别名
- `src/participant.rs` - 泛型化 Participant
- `src/dleq.rs` - 泛型化 DLEQ 证明
- `src/sharebox.rs` - 泛型化数据结构
- `src/mpvss.rs` - 重构为 ModpGroup（可删除，逻辑合并到 groups/modp.rs）
- `Cargo.toml` - 版本更新和依赖添加

### 保持不变
- `src/polynomial.rs` - 操作标量，与群类型无关
- `src/util.rs` - 纯数学工具函数

## 验证步骤

### 1. 单元测试
```bash
cargo test --release
```

### 2. MODP 示例
```bash
cargo run --release --example mpvss_all_modp
```

### 3. secp256k1 示例
```bash
cargo run --release --features secp256k1 --example mpvss_all_secp256k1
```

### 4. CI 检查
```bash
cargo fmt --all -- --check
cargo clippy --all
```

## 迁移指南（1.0.0）

### 旧代码（0.2.x）
```rust
let mut dealer = Participant::new();
dealer.initialize();
```

### 新代码（1.0.0）
```rust
// MODP（向后兼容方式）
let mut dealer = Participant::new(Arc::new(ModpGroup::new()));

// 或使用 secp256k1
let mut dealer = Participant::new(Arc::new(Secp256k1Group::new()));
```

## 风险和注意事项

1. **API 破坏性变更**: 升级至 1.0.0，需要清晰的迁移文档
2. **标量运算**: BigInt 和 k256::Scalar 运算需要适配
3. **序列化**: EC 点使用 SEC1 压缩格式
4. **性能**: EC 应比 MODP 快，但需要基准测试验证

## 时间估计

1. **阶段 1-2**: 分支 + Trait 定义（1-2 天）
2. **阶段 3-4**: 群实现（2-3 天）
3. **阶段 5-7**: 泛型化（3-4 天）
4. **阶段 8-9**: 集成和特殊情况处理（2-3 天）
5. **阶段 10**: 测试和文档（2-3 天）

总计：约 10-15 个工作日
