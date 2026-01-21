/**
 * Hytale Avatar Viewer - Three.js Rendering Module
 *
 * Usage:
 *   const viewer = new HytaleAvatarViewer(containerElement, options);
 *   await viewer.loadAvatar(uuid);
 *   viewer.setAnimation('Default/Idle');
 */

const SCALE = 0.01; // BlockyModel units to world units
const FPS = 60; // Hytale animations run at 60fps

class HytaleAvatarViewer {
  constructor(container, options = {}) {
    this.container = container;
    this.options = {
      autoRotate: options.autoRotate !== false,
      showGrid: options.showGrid !== false,
      backgroundColor: options.backgroundColor || 0x1a1a2e,
      ...options
    };

    this.scene = null;
    this.camera = null;
    this.renderer = null;
    this.character = null;
    this.modelData = null;
    this.wireframeMode = false;
    this.autoRotate = this.options.autoRotate;

    // Animation state
    this.currentAnimation = null;
    this.animationTime = 0;
    this.lastFrameTime = 0;
    this.animationEnabled = true;
    this.currentAnimationPath = 'Default/Idle';

    // Texture cache
    this.textureCache = new Map();
    this.textureLoader = null;

    // Body parts state
    this.hiddenBodyParts = new Set();
    this.polygonOffsetParts = new Set();
    this.originalTransforms = new Map();

    // Callbacks
    this.onLoadProgress = options.onLoadProgress || (() => {});
    this.onLoadComplete = options.onLoadComplete || (() => {});
    this.onError = options.onError || ((err) => console.error(err));
  }

  // Initialize Three.js scene
  init() {
    const width = this.container.clientWidth;
    const height = this.container.clientHeight;

    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(this.options.backgroundColor);

    this.camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    this.camera.position.set(0, 0.6, 2.0);
    this.camera.lookAt(0, 0.5, 0);

    this.renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: this.options.alpha !== false  // Enable alpha by default for transparency support
    });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(window.devicePixelRatio);
    this.container.appendChild(this.renderer.domElement);

    // Lighting
    this.scene.add(new THREE.AmbientLight(0xffffff, 0.7));
    const dirLight = new THREE.DirectionalLight(0xffffff, 0.6);
    dirLight.position.set(2, 3, 2);
    this.scene.add(dirLight);
    const backLight = new THREE.DirectionalLight(0xffffff, 0.3);
    backLight.position.set(-2, 1, -2);
    this.scene.add(backLight);
    const fillLight = new THREE.DirectionalLight(0xffffff, 0.2);
    fillLight.position.set(0, -1, 2);
    this.scene.add(fillLight);

    if (this.options.showGrid) {
      this.scene.add(new THREE.GridHelper(2, 10, 0x444444, 0x333333));
    }

    this.character = new THREE.Group();
    this.character.rotation.y = Math.PI; // Face camera
    this.scene.add(this.character);

    this.textureLoader = new THREE.TextureLoader();

    // Setup resize handler
    this._resizeHandler = () => {
      const w = this.container.clientWidth;
      const h = this.container.clientHeight;
      this.camera.aspect = w / h;
      this.camera.updateProjectionMatrix();
      this.renderer.setSize(w, h);
    };
    window.addEventListener('resize', this._resizeHandler);

    // Setup mouse/touch controls
    this._setupControls();

    return this;
  }

  _setupControls() {
    let isDragging = false;
    let prevX = 0;

    this.container.addEventListener('mousedown', (e) => {
      isDragging = true;
      prevX = e.clientX;
      this.autoRotate = false;
    });

    window.addEventListener('mouseup', () => isDragging = false);

    window.addEventListener('mousemove', (e) => {
      if (isDragging) {
        this.character.rotation.y += (e.clientX - prevX) * 0.01;
        prevX = e.clientX;
      }
    });

    this.container.addEventListener('touchstart', (e) => {
      isDragging = true;
      prevX = e.touches[0].clientX;
      this.autoRotate = false;
    });

    this.container.addEventListener('touchend', () => isDragging = false);

    this.container.addEventListener('touchmove', (e) => {
      if (isDragging) {
        this.character.rotation.y += (e.touches[0].clientX - prevX) * 0.01;
        prevX = e.touches[0].clientX;
      }
    });
  }

  // Load avatar by UUID
  async loadAvatar(uuid) {
    try {
      this.onLoadProgress('Fetching skin data...');
      const response = await fetch(`/avatar/${uuid}/model`);
      if (!response.ok) throw new Error('Failed to load avatar data');
      this.modelData = await response.json();
      if (this.modelData.error) throw new Error(this.modelData.error);

      // Determine hidden parts
      this._determineHiddenParts(this.modelData);

      this.onLoadProgress('Building character...');
      await this._buildCharacter(this.modelData);

      // Load default animation
      this.onLoadProgress('Loading animation...');
      this.currentAnimation = await this._loadAnimation(this.currentAnimationPath);

      this.lastFrameTime = performance.now();
      this._animate();

      this.onLoadComplete(this.modelData);
    } catch (err) {
      this.onError(err);
      throw err;
    }
  }

  // Load avatar from direct skin data (for customizer preview)
  async loadFromSkinData(skinData) {
    try {
      this.onLoadProgress('Building character...');

      // Clear existing character
      while (this.character.children.length > 0) {
        this.character.remove(this.character.children[0]);
      }
      this.originalTransforms.clear();
      this.hiddenBodyParts.clear();
      this.polygonOffsetParts.clear();

      // Build model data structure
      this.modelData = {
        skinTone: skinData.skinTone || '01',
        bodyType: skinData.bodyType || 'Regular',
        parts: {}
      };

      // This would need server-side resolution of parts
      // For now we'll reload from server

      this._determineHiddenParts(this.modelData);
      await this._buildCharacter(this.modelData);

      this.onLoadComplete(this.modelData);
    } catch (err) {
      this.onError(err);
      throw err;
    }
  }

  // Animation methods
  async setAnimation(animPath) {
    this.currentAnimationPath = animPath;
    this.animationTime = 0;

    if (!animPath) {
      this.currentAnimation = null;
      this._resetToOriginalPose();
      return;
    }

    this.currentAnimation = await this._loadAnimation(animPath);
  }

  setAutoRotate(enabled) {
    this.autoRotate = enabled;
  }

  setWireframe(enabled) {
    this.wireframeMode = enabled;
    this.character.traverse((c) => {
      if (c.isMesh) c.material.wireframe = enabled;
    });
  }

  resetView() {
    this.character.rotation.y = Math.PI;
  }

  rotate(amount) {
    this.character.rotation.y += amount;
  }

  // Cleanup
  destroy() {
    window.removeEventListener('resize', this._resizeHandler);
    if (this.renderer) {
      this.renderer.dispose();
      this.container.removeChild(this.renderer.domElement);
    }
    this.textureCache.clear();
  }

  // Private methods

  _determineHiddenParts(data) {
    if (data.parts?.pants || data.parts?.overpants) {
      this.hiddenBodyParts.add('Pelvis');
      this.hiddenBodyParts.add('L-Thigh');
      this.hiddenBodyParts.add('R-Thigh');
      this.hiddenBodyParts.add('L-Calf');
      this.hiddenBodyParts.add('R-Calf');
    }
    if (data.parts?.overtop || data.parts?.undertop) {
      this.hiddenBodyParts.add('Belly');
      this.hiddenBodyParts.add('Chest');
      this.polygonOffsetParts.add('L-Arm');
      this.polygonOffsetParts.add('R-Arm');
      this.polygonOffsetParts.add('L-Forearm');
      this.polygonOffsetParts.add('R-Forearm');
    }
    if (data.parts?.shoes) {
      this.hiddenBodyParts.add('L-Foot');
      this.hiddenBodyParts.add('R-Foot');
    }
    if (data.parts?.haircut) {
      this.hiddenBodyParts.add('HeadTop');
      this.hiddenBodyParts.add('HairBase');
    }
  }

  async _loadAnimation(animPath) {
    if (!animPath) return null;
    try {
      const response = await fetch('/asset/Common/Characters/Animations/' + animPath + '.blockyanim');
      if (!response.ok) return null;
      return await response.json();
    } catch (e) {
      console.error('[ANIMATION] Failed to load:', animPath, e);
      return null;
    }
  }

  _resetToOriginalPose() {
    this.originalTransforms.forEach((transform, nodeName) => {
      const node = this.character?.getObjectByName(nodeName);
      if (node) {
        node.position.copy(transform.position);
        node.quaternion.copy(transform.quaternion);
      }
    });
  }

  _animate() {
    requestAnimationFrame(() => this._animate());

    const now = performance.now();
    const deltaTime = (now - this.lastFrameTime) / 1000;
    this.lastFrameTime = now;

    if (this.animationEnabled && this.currentAnimation) {
      const clampedDelta = Math.min(deltaTime, 0.1);
      this.animationTime += clampedDelta * FPS;
      if (this.currentAnimation.holdLastKeyframe) {
        this.animationTime = Math.min(this.animationTime, this.currentAnimation.duration);
      }
      this._applyAnimation(this.currentAnimation, this.animationTime);
    }

    if (this.autoRotate) {
      this.character.rotation.y += 0.005;
    }

    this.renderer.render(this.scene, this.camera);
  }

  _applyAnimation(animation, time) {
    if (!animation || !animation.nodeAnimations || !this.character) return;

    const duration = animation.duration;
    const loopTime = ((time % duration) + duration) % duration;

    for (const [nodeName, nodeAnim] of Object.entries(animation.nodeAnimations)) {
      const node = this.character.getObjectByName(nodeName);
      if (!node) continue;

      if (!this.originalTransforms.has(nodeName)) {
        this.originalTransforms.set(nodeName, {
          position: node.position.clone(),
          quaternion: node.quaternion.clone()
        });
      }
      const original = this.originalTransforms.get(nodeName);

      if (nodeAnim.orientation && nodeAnim.orientation.length > 0) {
        const animQuat = this._interpolateQuaternion(nodeAnim.orientation, loopTime, duration);
        if (animQuat) {
          node.quaternion.copy(original.quaternion);
          node.quaternion.multiply(animQuat);
        }
      }

      if (nodeAnim.position && nodeAnim.position.length > 0) {
        const animPos = this._interpolatePosition(nodeAnim.position, loopTime, duration);
        if (animPos) {
          node.position.copy(original.position);
          node.position.add(animPos);
        }
      }
    }
  }

  _findKeyframes(keyframes, time, duration) {
    if (!keyframes || keyframes.length === 0) return null;
    if (keyframes.length === 1) {
      return { k1: keyframes[0], k2: keyframes[0], t: 0 };
    }

    const sorted = [...keyframes].sort((a, b) => a.time - b.time);

    let idx1 = -1;
    for (let i = 0; i < sorted.length; i++) {
      if (sorted[i].time <= time) idx1 = i;
      else break;
    }

    if (idx1 === -1) {
      const k1 = sorted[sorted.length - 1];
      const k2 = sorted[0];
      const t1 = k1.time;
      const t2 = k2.time + duration;
      const currentTime = time + duration;
      let t = (t2 - t1) > 0 ? (currentTime - t1) / (t2 - t1) : 0;
      t = Math.max(0, Math.min(1, t));
      return { k1, k2, t, smooth: k1.interpolationType === 'smooth' };
    }

    if (idx1 === sorted.length - 1) {
      const k1 = sorted[idx1];
      const k2 = sorted[0];
      const timeSpan = (duration - k1.time) + k2.time;
      const elapsed = time - k1.time;
      let t = timeSpan > 0 ? elapsed / timeSpan : 0;
      t = Math.max(0, Math.min(1, t));
      return { k1, k2, t, smooth: k1.interpolationType === 'smooth' };
    }

    const k1 = sorted[idx1];
    const k2 = sorted[idx1 + 1];
    const timeSpan = k2.time - k1.time;
    let t = timeSpan > 0 ? (time - k1.time) / timeSpan : 0;
    t = Math.max(0, Math.min(1, t));
    return { k1, k2, t, smooth: k1.interpolationType === 'smooth' };
  }

  _interpolateQuaternion(keyframes, time, duration) {
    const kf = this._findKeyframes(keyframes, time, duration);
    if (!kf) return null;

    const { k1, k2, smooth } = kf;
    let t = kf.t;

    const q1 = new THREE.Quaternion(k1.delta.x, k1.delta.y, k1.delta.z, k1.delta.w);
    const q2 = new THREE.Quaternion(k2.delta.x, k2.delta.y, k2.delta.z, k2.delta.w);

    if (smooth) t = t * t * (3 - 2 * t);

    const result = new THREE.Quaternion();
    result.slerpQuaternions(q1, q2, t);
    return result;
  }

  _interpolatePosition(keyframes, time, duration) {
    const kf = this._findKeyframes(keyframes, time, duration);
    if (!kf) return null;

    const { k1, k2, smooth } = kf;
    let t = kf.t;

    if (smooth) t = t * t * (3 - 2 * t);

    const v1 = new THREE.Vector3(k1.delta.x, k1.delta.y, k1.delta.z);
    const v2 = new THREE.Vector3(k2.delta.x, k2.delta.y, k2.delta.z);
    const result = new THREE.Vector3();
    result.lerpVectors(v1, v2, t);
    result.multiplyScalar(SCALE);
    return result;
  }

  // Texture loading
  async _loadTexture(path) {
    if (this.textureCache.has(path)) return this.textureCache.get(path);

    return new Promise((resolve) => {
      const fullPath = path.startsWith('Common/') ? '/asset/' + path : '/asset/Common/' + path;
      this.textureLoader.load(fullPath,
        (texture) => {
          texture.magFilter = THREE.NearestFilter;
          texture.minFilter = THREE.NearestFilter;
          texture.wrapS = THREE.ClampToEdgeWrapping;
          texture.wrapT = THREE.ClampToEdgeWrapping;
          texture.generateMipmaps = false;
          this.textureCache.set(path, texture);
          resolve(texture);
        },
        undefined,
        () => {
          const altPath = '/asset/' + path.replace('Common/', '');
          this.textureLoader.load(altPath,
            (texture) => {
              texture.magFilter = THREE.NearestFilter;
              texture.minFilter = THREE.NearestFilter;
              texture.wrapS = THREE.ClampToEdgeWrapping;
              texture.wrapT = THREE.ClampToEdgeWrapping;
              texture.generateMipmaps = false;
              this.textureCache.set(path, texture);
              resolve(texture);
            },
            undefined,
            () => resolve(null)
          );
        }
      );
    });
  }

  _createCanvasTexture(canvas) {
    const texture = new THREE.CanvasTexture(canvas);
    texture.magFilter = THREE.NearestFilter;
    texture.minFilter = THREE.NearestFilter;
    texture.wrapS = THREE.ClampToEdgeWrapping;
    texture.wrapT = THREE.ClampToEdgeWrapping;
    texture.generateMipmaps = false;
    texture.userData = { width: canvas.width, height: canvas.height };
    return texture;
  }

  async _loadGradientData(gradientTexturePath) {
    if (!gradientTexturePath) return null;
    try {
      const gradientTexture = await this._loadTexture(gradientTexturePath);
      if (gradientTexture && gradientTexture.image) {
        const canvas = document.createElement('canvas');
        canvas.width = gradientTexture.image.width;
        canvas.height = gradientTexture.image.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(gradientTexture.image, 0, 0);
        return ctx.getImageData(0, 0, canvas.width, canvas.height);
      }
    } catch (e) {
      console.error('[TINT] Gradient load error:', e);
    }
    return null;
  }

  async _createTintedTexture(greyscalePath, baseColor, gradientTexturePath = null) {
    const texture = await this._loadTexture(greyscalePath);
    if (!texture || !texture.image) return null;

    const canvas = document.createElement('canvas');
    const img = texture.image;
    canvas.width = img.width;
    canvas.height = img.height;

    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;
    const gradientData = await this._loadGradientData(gradientTexturePath);
    const color = this._parseColor(baseColor);

    for (let i = 0; i < data.length; i += 4) {
      const origR = data[i];
      const origG = data[i + 1];
      const origB = data[i + 2];
      const alpha = data[i + 3];

      if (alpha > 0) {
        const isGreyscale = (origR === origG) && (origG === origB);

        if (isGreyscale) {
          const grey = origR;
          let r, g, b;

          if (gradientData) {
            const gradX = Math.min(grey, gradientData.width - 1);
            const gradIdx = gradX * 4;
            r = gradientData.data[gradIdx];
            g = gradientData.data[gradIdx + 1];
            b = gradientData.data[gradIdx + 2];
          } else if (color) {
            const t = grey / 255;
            r = Math.round(Math.min(255, color.r * t * 2));
            g = Math.round(Math.min(255, color.g * t * 2));
            b = Math.round(Math.min(255, color.b * t * 2));
          } else {
            r = grey; g = grey; b = grey;
          }

          data[i] = r;
          data[i + 1] = g;
          data[i + 2] = b;
        }
      }
    }

    ctx.putImageData(imageData, 0, 0);
    return this._createCanvasTexture(canvas);
  }

  async _createEyeShadowTexture(originalTexture) {
    if (!originalTexture || !originalTexture.image) return null;

    const img = originalTexture.image;
    const canvas = document.createElement('canvas');
    canvas.width = img.width;
    canvas.height = img.height;
    const ctx = canvas.getContext('2d');

    ctx.drawImage(img, 0, 0);
    const imageData = ctx.getImageData(0, 0, img.width, img.height);
    const data = imageData.data;

    for (let y = 0; y < img.height; y++) {
      for (let x = 0; x < img.width; x++) {
        const idx = (y * img.width + x) * 4;
        const a = data[idx + 3];

        if (y < 16 && a > 0) {
          let localX = -1, localY = -1;
          if (x >= 1 && x < 15 && y >= 1 && y < 15) {
            localX = x - 1;
            localY = y - 1;
          } else if (x >= 17 && x < 31 && y >= 1 && y < 15) {
            localX = x - 17;
            localY = y - 1;
          }

          if (localX >= 0 && localY >= 0) {
            let shadowAlpha = 0;
            if (localY < 4) {
              shadowAlpha = (1 - localY / 4) * 0.25;
            }
            data[idx] = 0;
            data[idx + 1] = 0;
            data[idx + 2] = 0;
            data[idx + 3] = Math.round(shadowAlpha * 255 * (a / 255));
          } else {
            data[idx + 3] = 0;
          }
        }
      }
    }

    ctx.putImageData(imageData, 0, 0);
    return this._createCanvasTexture(canvas);
  }

  _parseColor(color) {
    if (typeof color === 'number') {
      return {
        r: (color >> 16) & 255,
        g: (color >> 8) & 255,
        b: color & 255
      };
    }
    if (typeof color === 'string') {
      if (color.startsWith('#')) {
        const hex = color.slice(1);
        return {
          r: parseInt(hex.substr(0, 2), 16),
          g: parseInt(hex.substr(2, 2), 16),
          b: parseInt(hex.substr(4, 2), 16)
        };
      }
    }
    if (Array.isArray(color)) {
      return this._parseColor(color[0]);
    }
    return { r: 200, g: 200, b: 200 };
  }

  // Character building
  async _buildCharacter(data) {
    const skinColor = this._getSkinToneColor(data.skinTone);
    const skinColorHex = '#' + skinColor.toString(16).padStart(6, '0');
    const skinToneGradient = this._getSkinToneGradientPath(data.skinTone);

    // Load base player model
    this.onLoadProgress('Loading player model...');
    try {
      const playerModel = await this._fetchModel('Common/Characters/Player.blockymodel');
      if (playerModel) {
        const bodyTexturePath = data.bodyType === 'Muscular'
          ? 'Characters/Player_Textures/Player_Muscular_Greyscale.png'
          : 'Characters/Player_Textures/Player_Greyscale.png';

        const bodyTexture = await this._createTintedTexture(bodyTexturePath, skinColorHex, skinToneGradient);
        await this._renderPlayerModel(playerModel.nodes, this.character, skinColor, bodyTexture);
      }
    } catch (e) {
      console.error('[AVATAR] Could not load player model:', e);
    }

    // Cosmetics render order
    const cosmeticOrder = [
      { key: 'underwear', zOffset: 0 },
      { key: 'pants', zOffset: 0.001 },
      { key: 'overpants', zOffset: 0.002 },
      { key: 'shoes', zOffset: 0.001 },
      { key: 'undertop', zOffset: 0.001 },
      { key: 'overtop', zOffset: 0.002 },
      { key: 'gloves', zOffset: 0.001 },
      { key: 'face', zOffset: 0.01 },
      { key: 'mouth', zOffset: 0.015 },
      { key: 'eyes', zOffset: 0.02 },
      { key: 'eyebrows', zOffset: 0.025 },
      { key: 'ears', zOffset: 0 },
      { key: 'haircut', zOffset: 0.005 },
      { key: 'facialHair', zOffset: 0.004 },
      { key: 'headAccessory', zOffset: 0.006 },
      { key: 'faceAccessory', zOffset: 0.005 },
      { key: 'earAccessory', zOffset: 0.001 },
      { key: 'cape', zOffset: -0.001 }
    ];

    for (const { key, zOffset } of cosmeticOrder) {
      const part = data.parts?.[key];
      if (part && part.model) {
        this.onLoadProgress(`Loading ${key}...`);

        let color = this._getPartColor(part);
        if (!color) {
          if (['face', 'ears'].includes(key)) {
            color = skinColor;
          } else {
            color = this._getDefaultColor(key, skinColor);
          }
        }

        let texture = null;
        const isSkinPart = part.gradientSet === 'Skin' || ['face', 'ears', 'mouth'].includes(key);

        if (part.texture) {
          texture = await this._loadTexture(part.texture);
        } else if (part.greyscaleTexture) {
          let gradientPath = part.gradientTexture;
          let baseCol = part.baseColor;

          if (isSkinPart) {
            gradientPath = skinToneGradient;
            baseCol = skinColorHex;
            color = skinColor;
          }

          if (!gradientPath && !baseCol) {
            baseCol = '#' + this._getDefaultColor(key, skinColor).toString(16).padStart(6, '0');
          }

          texture = await this._createTintedTexture(part.greyscaleTexture, baseCol, gradientPath);
        }

        try {
          let modelPath = part.model;
          if (!modelPath.startsWith('Common/')) modelPath = 'Common/' + modelPath;
          const model = await this._fetchModel(modelPath);
          if (model) {
            let shadowTexture = null;
            if (key === 'eyes' && texture) {
              shadowTexture = await this._createEyeShadowTexture(texture);
            }
            await this._renderCosmeticModel(model.nodes, this.character, color, key, texture, zOffset, shadowTexture);
          }
        } catch (e) {
          console.error(`[COSMETIC] ${key} error:`, e);
        }
      }
    }
  }

  async _fetchModel(path) {
    const response = await fetch('/asset/' + path);
    if (!response.ok) return null;
    return response.json();
  }

  async _renderPlayerModel(nodes, parent, skinColor, bodyTexture) {
    if (!nodes) return;
    for (const node of nodes) {
      this._renderPlayerNode(node, parent, skinColor, bodyTexture, 0);
    }
  }

  _renderPlayerNode(node, parent, skinColor, bodyTexture, depth = 0) {
    const nodeName = node.name || node.id || '';

    if (this.hiddenBodyParts.has(nodeName)) {
      const group = new THREE.Group();
      group.name = nodeName;
      this._applyTransform(group, node);
      parent.add(group);
      if (node.children) {
        for (const child of node.children) {
          this._renderPlayerNode(child, group, skinColor, bodyTexture, depth + 1);
        }
      }
      return;
    }

    const group = new THREE.Group();
    group.name = nodeName;
    this._applyTransform(group, node);

    const usePolygonOffset = this.polygonOffsetParts.has(nodeName);
    if (node.shape && node.shape.visible !== false && node.shape.type === 'box') {
      const mesh = this._createBoxMesh(node.shape, skinColor, nodeName, bodyTexture, usePolygonOffset);
      if (mesh) group.add(mesh);
    } else if (node.shape && node.shape.type === 'quad') {
      const mesh = this._createQuadMesh(node.shape, skinColor, nodeName, bodyTexture);
      if (mesh) group.add(mesh);
    }

    parent.add(group);

    if (node.children) {
      for (const child of node.children) {
        this._renderPlayerNode(child, group, skinColor, bodyTexture, depth + 1);
      }
    }
  }

  async _renderCosmeticModel(nodes, parent, color, partType, texture, zOffset, shadowTexture = null) {
    if (!nodes) return;
    for (const node of nodes) {
      this._renderCosmeticNode(node, parent, color, partType, texture, zOffset, 0, shadowTexture);
    }
  }

  _findBoneByName(parent, name) {
    if (!name) return null;
    let found = null;
    parent.traverse((obj) => {
      if (obj.name === name && !found) found = obj;
    });
    return found;
  }

  _renderCosmeticNode(node, parent, color, partType, texture, zOffset, depth = 0, shadowTexture = null) {
    const nodeName = node.name || node.id || '';

    let targetParent = parent;
    let attachedToPlayerBone = false;
    if (nodeName) {
      const matchingBone = this._findBoneByName(this.character, nodeName);
      if (matchingBone) {
        targetParent = matchingBone;
        attachedToPlayerBone = true;
      }
    }

    const group = new THREE.Group();
    group.name = nodeName + '_cosmetic';

    if (attachedToPlayerBone) {
      if (node.orientation) {
        group.quaternion.set(
          node.orientation.x || 0,
          node.orientation.y || 0,
          node.orientation.z || 0,
          node.orientation.w || 1
        );
      }
    } else {
      this._applyTransform(group, node);
    }

    if (zOffset) {
      group.position.z += zOffset;
    }

    if (node.shape && node.shape.visible !== false && node.shape.type !== 'none') {
      let mesh = null;
      if (node.shape.type === 'box') {
        mesh = this._createBoxMesh(node.shape, color, nodeName, texture);
      } else if (node.shape.type === 'quad') {
        if (partType === 'eyes' && nodeName.includes('Background') && shadowTexture) {
          mesh = this._createQuadMesh(node.shape, color, nodeName, shadowTexture);
          mesh.renderOrder = 100;
          mesh.material.transparent = true;
          mesh.material.depthWrite = false;
          mesh.material.alphaTest = 0;
          mesh.material.blending = THREE.NormalBlending;
        } else {
          mesh = this._createQuadMesh(node.shape, color, nodeName, texture);

          if (mesh && partType === 'eyes' && nodeName.includes('Eye') && !nodeName.includes('Attachment') && !nodeName.includes('Background')) {
            mesh.renderOrder = 101;
          }
        }

        if (mesh && partType === 'mouth') {
          mesh.renderOrder = 99;
        } else if (mesh && partType === 'face') {
          mesh.renderOrder = 98;
        }
      }
      if (mesh) group.add(mesh);
    }

    targetParent.add(group);

    if (node.children) {
      for (const child of node.children) {
        const childName = child.name || child.id || '';
        const childBone = this._findBoneByName(this.character, childName);
        if (childBone) {
          this._renderCosmeticNode(child, childBone, color, partType, texture, zOffset, depth + 1, shadowTexture);
        } else {
          this._renderCosmeticNode(child, group, color, partType, texture, 0, depth + 1, shadowTexture);
        }
      }
    }
  }

  _applyTransform(group, node) {
    if (node.orientation) {
      group.quaternion.set(
        node.orientation.x || 0,
        node.orientation.y || 0,
        node.orientation.z || 0,
        node.orientation.w || 1
      );
    }

    let posX = (node.position?.x || 0) * SCALE;
    let posY = (node.position?.y || 0) * SCALE;
    let posZ = (node.position?.z || 0) * SCALE;

    if (node.shape && node.shape.offset) {
      const offset = new THREE.Vector3(
        (node.shape.offset.x || 0) * SCALE,
        (node.shape.offset.y || 0) * SCALE,
        (node.shape.offset.z || 0) * SCALE
      );
      offset.applyQuaternion(group.quaternion);
      posX += offset.x;
      posY += offset.y;
      posZ += offset.z;
    }

    group.position.set(posX, posY, posZ);
  }

  _createBoxMesh(shape, color, nodeName, texture = null, usePolygonOffset = false) {
    const settings = shape.settings;
    if (!settings || !settings.size) return null;

    const stretch = shape.stretch || { x: 1, y: 1, z: 1 };
    const sx = Math.abs(stretch.x || 1);
    const sy = Math.abs(stretch.y || 1);
    const sz = Math.abs(stretch.z || 1);

    const flipX = (stretch.x || 1) < 0;
    const flipY = (stretch.y || 1) < 0;
    const flipZ = (stretch.z || 1) < 0;

    const width = settings.size.x * sx * SCALE;
    const height = settings.size.y * sy * SCALE;
    const depth = settings.size.z * sz * SCALE;

    const pixelW = settings.size.x;
    const pixelH = settings.size.y;
    const pixelD = settings.size.z;

    const hasTextureLayout = texture && shape.textureLayout && Object.keys(shape.textureLayout).length > 0;
    const geometry = new THREE.BoxGeometry(width, height, depth);

    if (hasTextureLayout) {
      const texW = texture.image?.width || texture.userData?.width;
      const texH = texture.image?.height || texture.userData?.height;

      if (texW && texH) {
        const faceMap = ['right', 'left', 'top', 'bottom', 'front', 'back'];
        const uvAttr = geometry.getAttribute('uv');
        const uvArray = uvAttr.array;

        for (let faceIdx = 0; faceIdx < 6; faceIdx++) {
          const faceName = faceMap[faceIdx];
          const layout = shape.textureLayout[faceName];

          if (layout && layout.offset) {
            const angle = layout.angle || 0;

            let uv_size = [0, 0];
            if (faceName === 'left' || faceName === 'right') {
              uv_size = [pixelD, pixelH];
            } else if (faceName === 'top' || faceName === 'bottom') {
              uv_size = [pixelW, pixelD];
            } else {
              uv_size = [pixelW, pixelH];
            }

            let uv_mirror = [
              layout.mirror?.x ? -1 : 1,
              layout.mirror?.y ? -1 : 1
            ];

            const uv_offset = [layout.offset.x, layout.offset.y];

            let result;
            switch (angle) {
              case 90:
                [uv_size[0], uv_size[1]] = [uv_size[1], uv_size[0]];
                [uv_mirror[0], uv_mirror[1]] = [uv_mirror[1], uv_mirror[0]];
                uv_mirror[0] *= -1;
                result = [
                  uv_offset[0],
                  uv_offset[1] + uv_size[1] * uv_mirror[1],
                  uv_offset[0] + uv_size[0] * uv_mirror[0],
                  uv_offset[1]
                ];
                break;
              case 180:
                uv_mirror[0] *= -1;
                uv_mirror[1] *= -1;
                result = [
                  uv_offset[0] + uv_size[0] * uv_mirror[0],
                  uv_offset[1] + uv_size[1] * uv_mirror[1],
                  uv_offset[0],
                  uv_offset[1]
                ];
                break;
              case 270:
                [uv_size[0], uv_size[1]] = [uv_size[1], uv_size[0]];
                [uv_mirror[0], uv_mirror[1]] = [uv_mirror[1], uv_mirror[0]];
                uv_mirror[1] *= -1;
                result = [
                  uv_offset[0] + uv_size[0] * uv_mirror[0],
                  uv_offset[1],
                  uv_offset[0],
                  uv_offset[1] + uv_size[1] * uv_mirror[1]
                ];
                break;
              default:
                result = [
                  uv_offset[0],
                  uv_offset[1],
                  uv_offset[0] + uv_size[0] * uv_mirror[0],
                  uv_offset[1] + uv_size[1] * uv_mirror[1]
                ];
                break;
            }

            const u1 = result[0] / texW;
            const v1 = 1.0 - result[1] / texH;
            const u2 = result[2] / texW;
            const v2 = 1.0 - result[3] / texH;

            const baseIdx = faceIdx * 4 * 2;
            uvArray[baseIdx + 0] = u1; uvArray[baseIdx + 1] = v1;
            uvArray[baseIdx + 2] = u2; uvArray[baseIdx + 3] = v1;
            uvArray[baseIdx + 4] = u1; uvArray[baseIdx + 5] = v2;
            uvArray[baseIdx + 6] = u2; uvArray[baseIdx + 7] = v2;
          }
        }
        uvAttr.needsUpdate = true;
      }
    }

    const needsDoubleSide = flipX || flipY || flipZ;

    let material;
    if (texture) {
      const isBodyPart = ['Neck', 'Head', 'Chest', 'Belly', 'Pelvis'].includes(nodeName) ||
                         nodeName.includes('Arm') || nodeName.includes('Leg') ||
                         nodeName.includes('Hand') || nodeName.includes('Foot') ||
                         nodeName.includes('Thigh') || nodeName.includes('Calf');
      material = new THREE.MeshLambertMaterial({
        map: texture,
        wireframe: this.wireframeMode,
        alphaTest: isBodyPart ? 0 : 0.1,
        transparent: !isBodyPart,
        side: needsDoubleSide ? THREE.DoubleSide : THREE.FrontSide,
        depthWrite: true,
        polygonOffset: usePolygonOffset,
        polygonOffsetFactor: usePolygonOffset ? 1 : 0,
        polygonOffsetUnits: usePolygonOffset ? 1 : 0
      });
    } else {
      material = new THREE.MeshLambertMaterial({
        color: color,
        wireframe: this.wireframeMode,
        side: needsDoubleSide ? THREE.DoubleSide : THREE.FrontSide,
        polygonOffset: usePolygonOffset,
        polygonOffsetFactor: usePolygonOffset ? 1 : 0,
        polygonOffsetUnits: usePolygonOffset ? 1 : 0
      });
    }

    const mesh = new THREE.Mesh(geometry, material);

    if (flipX) mesh.scale.x = -1;
    if (flipY) mesh.scale.y = -1;
    if (flipZ) mesh.scale.z = -1;

    return mesh;
  }

  _createQuadMesh(shape, color, nodeName, texture = null, renderOrder = 0) {
    const settings = shape.settings;
    if (!settings || !settings.size) return null;

    const stretch = shape.stretch || { x: 1, y: 1, z: 1 };
    const sx = Math.abs(stretch.x || 1);
    const sy = Math.abs(stretch.y || 1);
    const sz = Math.abs(stretch.z || 1);

    const flipX = (stretch.x || 1) < 0;
    const flipY = (stretch.y || 1) < 0;

    const normal = settings.normal || '+Z';
    const pixelW = settings.size.x;
    const pixelH = settings.size.y;

    let width, height;
    if (normal === '+Z' || normal === '-Z') {
      width = pixelW * sx * SCALE;
      height = pixelH * sy * SCALE;
    } else if (normal === '+X' || normal === '-X') {
      width = pixelW * sz * SCALE;
      height = pixelH * sy * SCALE;
    } else {
      width = pixelW * sx * SCALE;
      height = pixelH * sz * SCALE;
    }

    const geometry = new THREE.PlaneGeometry(width, height);

    if (normal === '-Z') {
      geometry.rotateY(Math.PI);
    } else if (normal === '+X') {
      geometry.rotateY(Math.PI / 2);
    } else if (normal === '-X') {
      geometry.rotateY(-Math.PI / 2);
    } else if (normal === '+Y') {
      geometry.rotateX(-Math.PI / 2);
    } else if (normal === '-Y') {
      geometry.rotateX(Math.PI / 2);
    }

    const hasTextureLayout = texture && shape.textureLayout && shape.textureLayout.front;
    if (hasTextureLayout) {
      const texW = texture.image?.width || texture.userData?.width;
      const texH = texture.image?.height || texture.userData?.height;

      if (texW && texH) {
        const layout = shape.textureLayout.front;
        if (layout && layout.offset) {
          const angle = layout.angle || 0;
          const mirrorX = layout.mirror?.x || false;
          const mirrorY = layout.mirror?.y || false;

          const x = layout.offset.x;
          const x2 = layout.offset.x + (mirrorX ? -1 : 1) * pixelW;
          const vTop = 1.0 - layout.offset.y / texH;
          const vBottom = 1.0 - (layout.offset.y + (mirrorY ? -1 : 1) * pixelH) / texH;

          let uvs = [
            [x / texW, vTop],
            [x2 / texW, vTop],
            [x / texW, vBottom],
            [x2 / texW, vBottom]
          ];

          if (angle !== 0) {
            const cx = (x + x2) / 2 / texW;
            const cy = (vTop + vBottom) / 2;
            const rad = -angle * Math.PI / 180;
            const cos = Math.cos(rad);
            const sin = Math.sin(rad);
            uvs = uvs.map(function(uv) {
              const du = uv[0] - cx;
              const dv = uv[1] - cy;
              return [cx + du * cos - dv * sin, cy + du * sin + dv * cos];
            });
          }

          const newUVs = new Float32Array([
            uvs[0][0], uvs[0][1],
            uvs[1][0], uvs[1][1],
            uvs[2][0], uvs[2][1],
            uvs[3][0], uvs[3][1]
          ]);
          geometry.setAttribute('uv', new THREE.BufferAttribute(newUVs, 2));
        }
      }
    }

    let material;
    if (texture) {
      material = new THREE.MeshLambertMaterial({
        map: texture,
        wireframe: this.wireframeMode,
        alphaTest: 0.5,
        transparent: false,
        side: THREE.DoubleSide,
        depthWrite: true,
        depthTest: true
      });
    } else {
      material = new THREE.MeshLambertMaterial({
        color: color,
        wireframe: this.wireframeMode,
        side: THREE.DoubleSide
      });
    }

    const mesh = new THREE.Mesh(geometry, material);

    if (renderOrder !== 0) {
      mesh.renderOrder = renderOrder;
    }

    if (flipX) mesh.scale.x = -1;
    if (flipY) mesh.scale.y = -1;

    return mesh;
  }

  // Skin tone data
  _getSkinToneColor(tone) {
    const tones = {
      '01': 0xf4c39a, '02': 0xf5c490, '03': 0xe0ae72, '04': 0xba7f5b,
      '05': 0x945d44, '06': 0x6f3b2c, '07': 0x4f2a24, '08': 0xdcc7a8,
      '09': 0xf5bc83, '10': 0xd98c5b, '11': 0xab7a4c, '12': 0x7d432b,
      '13': 0x513425, '14': 0x31221f, '15': 0xd5a082, '16': 0x63492f,
      '17': 0x5e3a2f, '18': 0x4d272b, '19': 0x8aacfb, '20': 0xa78af1,
      '21': 0xfc8572, '22': 0x9bc55d, '25': 0x4354e6, '26': 0x6c2abd,
      '27': 0x765e48, '28': 0xf3f3f3, '29': 0x998d71, '30': 0x50843a,
      '31': 0xb22a2a, '32': 0x3276c3, '33': 0x092029, '35': 0x5eae37,
      '36': 0xff72c2, '37': 0xf4c944, '38': 0x6c3f40, '39': 0xff9c5b,
      '41': 0xff95cd, '42': 0xa0dfff, '45': 0xd5f0a0, '46': 0xddbfe8,
      '47': 0xf0b9f2, '48': 0xdcc5b0, '49': 0xec6ff7, '50': 0x2b2b2f,
      '51': 0xf06f47, '52': 0x131111
    };
    return tones[tone] || tones['01'];
  }

  _getSkinToneGradientPath(tone) {
    const validTones = ['01','02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','25','26','27','28','29','30','31','32','33','35','36','37','38','39','41','42','45','46','47','48','49','50','51','52'];
    if (validTones.includes(tone)) {
      return `TintGradients/Skin_Tones/${tone}.png`;
    }
    return 'TintGradients/Skin_Tones/01.png';
  }

  _getPartColor(part) {
    if (!part) return null;
    if (part.baseColor) {
      const bc = Array.isArray(part.baseColor) ? part.baseColor[0] : part.baseColor;
      if (typeof bc === 'string' && bc.startsWith('#')) {
        return parseInt(bc.slice(1), 16);
      }
    }
    return null;
  }

  _getDefaultColor(type, skinColor) {
    const defaults = {
      'haircut': 0x4a3728, 'facialHair': 0x4a3728, 'eyebrows': 0x4a3728,
      'pants': 0x2c3e50, 'overpants': 0x34495e,
      'undertop': 0x5dade2, 'overtop': 0x2980b9,
      'shoes': 0x1a1a1a, 'gloves': 0x8b4513,
      'face': skinColor, 'mouth': 0xc0392b, 'ears': skinColor,
      'eyes': 0x3498db, 'underwear': 0xecf0f1, 'cape': 0x8e44ad,
      'headAccessory': 0xf1c40f, 'faceAccessory': 0xbdc3c7, 'earAccessory': 0xf1c40f
    };
    return defaults[type] || 0x888888;
  }
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = HytaleAvatarViewer;
}
