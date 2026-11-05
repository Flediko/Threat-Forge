/**
 * ThreatForge — Enterprise Cyber Defense Wave & Telemetry Matrix
 * =============================================================
 * Implements a modern, high-tech cyber defense grid and continuous
 * threat wave mesh in Electric Indigo (#6366f1) and Frost Cyan (#38bdf8).
 * 
 * Replaces the old rotating green blob with:
 * - 3D Undulating Cyber Wave Topology (continuous dynamic sine/cosine mesh)
 * - Deep Horizon Perspective Data Streams
 * - Orbiting Concentric Defense Coordinates & Pulse Satellites
 * - Interactive Mouse Parallax
 * - High-efficiency canvas 2D rendering with automatic tab pause
 */

(function () {
    'use strict';

    class CyberDefenseGrid {
        constructor(canvasId) {
            this.canvas = document.getElementById(canvasId);
            if (!this.canvas) return;

            this.ctx = this.canvas.getContext('2d');
            if (!this.ctx) return;

            this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            this.isRunning = true;
            this.time = 0;
            this.mouseX = 0;
            this.mouseY = 0;
            this.targetMouseX = 0;
            this.targetMouseY = 0;
            this.lastFrameTime = performance.now();

            this.resize();
            this.initStreamParticles();
            this.initEvents();

            requestAnimationFrame(this.render.bind(this));
        }

        resize() {
            const dpr = Math.min(window.devicePixelRatio || 1, 2);
            this.width = window.innerWidth;
            this.height = window.innerHeight;
            this.canvas.width = this.width * dpr;
            this.canvas.height = this.height * dpr;
            this.ctx.setTransform(1, 0, 0, 1, 0, 0);
            this.ctx.scale(dpr, dpr);
        }

        initStreamParticles() {
            this.packets = [];
            const count = this.reducedMotion ? 18 : 36;
            for (let i = 0; i < count; i++) {
                this.packets.push({
                    x: Math.random() * this.width,
                    y: Math.random() * this.height,
                    speed: 0.6 + Math.random() * 1.2,
                    length: 20 + Math.random() * 40,
                    alpha: 0.15 + Math.random() * 0.45,
                    color: Math.random() > 0.4 ? 'rgba(99, 102, 241,' : 'rgba(56, 189, 248,'
                });
            }
        }

        initEvents() {
            window.addEventListener('resize', () => {
                this.resize();
                this.initStreamParticles();
            });

            window.addEventListener('mousemove', (e) => {
                if (this.reducedMotion) return;
                this.targetMouseX = (e.clientX / this.width - 0.5) * 40;
                this.targetMouseY = (e.clientY / this.height - 0.5) * 30;
            });

            document.addEventListener('visibilitychange', () => {
                this.isRunning = !document.hidden;
                if (this.isRunning) {
                    this.lastFrameTime = performance.now();
                    requestAnimationFrame(this.render.bind(this));
                }
            });

            const toggleBtn = document.getElementById('toggle-3d-btn');
            if (toggleBtn) {
                toggleBtn.addEventListener('click', () => {
                    this.isRunning = !this.isRunning;
                    toggleBtn.setAttribute('aria-pressed', String(this.isRunning));
                    toggleBtn.classList.toggle('active', this.isRunning);
                    const labelEl = toggleBtn.querySelector('.tf-3d-text') || toggleBtn;
                    labelEl.innerText = this.isRunning ? '3D Matrix: On' : '3D Matrix: Off';
                    if (this.isRunning) {
                        this.lastFrameTime = performance.now();
                        requestAnimationFrame(this.render.bind(this));
                    }
                });
            }
        }

        render(timestamp) {
            if (!this.isRunning) return;

            const dt = Math.min((timestamp - this.lastFrameTime) / 1000, 0.1);
            this.lastFrameTime = timestamp;

            if (!this.reducedMotion) {
                this.time += dt * 0.95;
                this.mouseX += (this.targetMouseX - this.mouseX) * 0.05;
                this.mouseY += (this.targetMouseY - this.mouseY) * 0.05;
            }

            const ctx = this.ctx;
            ctx.clearRect(0, 0, this.width, this.height);

            // 1. Draw Deep Ambient Vignette & Horizon Glow
            this.drawBackgroundGlow(ctx);

            // 2. Draw Moving Data Packets / Telemetry Streams
            this.drawTelemetryStreams(ctx);

            // 3. Draw 3D Dynamic Cyber Threat Wave Grid
            this.drawThreatWaveGrid(ctx);

            // 4. Draw Orbiting Concentric Defense Coordinates
            this.drawOrbitalCoordinates(ctx);

            requestAnimationFrame(this.render.bind(this));
        }

        drawBackgroundGlow(ctx) {
            const cx = this.width * 0.5 + this.mouseX * 0.5;
            const cy = this.height * 0.45 + this.mouseY * 0.5;

            // Deep central electric violet & cyan radial luminescence
            const grad = ctx.createRadialGradient(cx, cy, 50, cx, cy, Math.max(this.width, this.height) * 0.7);
            grad.addColorStop(0, 'rgba(99, 102, 241, 0.07)');
            grad.addColorStop(0.35, 'rgba(56, 189, 248, 0.035)');
            grad.addColorStop(1, 'rgba(7, 10, 18, 0)');

            ctx.fillStyle = grad;
            ctx.fillRect(0, 0, this.width, this.height);
        }

        drawTelemetryStreams(ctx) {
            ctx.save();
            ctx.lineWidth = 1.2;

            for (let i = 0; i < this.packets.length; i++) {
                const p = this.packets[i];
                if (!this.reducedMotion) {
                    p.y -= p.speed * 1.4;
                    if (p.y < -p.length) {
                        p.y = this.height + p.length;
                        p.x = Math.random() * this.width;
                    }
                }

                const grad = ctx.createLinearGradient(p.x, p.y + p.length, p.x, p.y);
                grad.addColorStop(0, `${p.color} 0)`);
                grad.addColorStop(1, `${p.color} ${p.alpha})`);

                ctx.strokeStyle = grad;
                ctx.beginPath();
                ctx.moveTo(p.x, p.y + p.length);
                ctx.lineTo(p.x, p.y);
                ctx.stroke();

                // Spark head
                ctx.fillStyle = '#ffffff';
                ctx.beginPath();
                ctx.arc(p.x, p.y, 1.2, 0, Math.PI * 2);
                ctx.fill();
            }

            ctx.restore();
        }

        drawThreatWaveGrid(ctx) {
            ctx.save();
            const horizonY = this.height * 0.58 + this.mouseY * 0.4;
            const rows = 16;
            const cols = 28;
            const spacingX = this.width / (cols - 1);
            const gridDepth = this.height - horizonY;

            // Compute grid vertices with undulating sine wave
            const points = [];
            for (let r = 0; r < rows; r++) {
                const rowProgress = r / (rows - 1);
                // Perspective exponential spacing for true 3D depth
                const depthFactor = Math.pow(rowProgress, 1.8);
                const y = horizonY + depthFactor * gridDepth;

                const rowPoints = [];
                for (let c = 0; c < cols; c++) {
                    const xProgress = c / (cols - 1);
                    // Vanishing point convergence towards horizon center
                    const vanishFactor = (xProgress - 0.5) * (0.25 + 0.85 * depthFactor);
                    const x = (this.width * 0.5) + (vanishFactor * this.width) + (this.mouseX * (1 - depthFactor) * 0.4);

                    // Multi-frequency wave displacement
                    const wave1 = Math.sin(c * 0.4 + this.time * 1.5 + r * 0.3) * 14 * depthFactor;
                    const wave2 = Math.cos(r * 0.5 - this.time * 1.2) * 8 * depthFactor;
                    const finalY = y + wave1 + wave2;

                    rowPoints.push({ x, y: finalY, alpha: Math.min(1, depthFactor * 1.1) });
                }
                points.push(rowPoints);
            }

            // Draw horizontal wave lines
            for (let r = 0; r < rows; r++) {
                const rowAlpha = points[r][0].alpha * 0.28;
                if (rowAlpha <= 0.01) continue;

                ctx.strokeStyle = `rgba(99, 102, 241, ${rowAlpha})`;
                ctx.lineWidth = 1 + (r / rows) * 0.8;
                ctx.beginPath();
                for (let c = 0; c < cols; c++) {
                    const p = points[r][c];
                    if (c === 0) ctx.moveTo(p.x, p.y);
                    else ctx.lineTo(p.x, p.y);
                }
                ctx.stroke();
            }

            // Draw radiating perspective columns
            for (let c = 0; c < cols; c += 2) {
                ctx.beginPath();
                for (let r = 0; r < rows; r++) {
                    const p = points[r][c];
                    if (r === 0) ctx.moveTo(p.x, p.y);
                    else ctx.lineTo(p.x, p.y);
                }
                ctx.strokeStyle = 'rgba(56, 189, 248, 0.08)';
                ctx.lineWidth = 0.9;
                ctx.stroke();
            }

            // Pulse glowing crest nodes at wave peaks
            for (let r = 4; r < rows; r += 3) {
                for (let c = 3; c < cols; c += 4) {
                    const p = points[r][c];
                    const pulse = 0.3 + Math.sin(this.time * 2 + c + r) * 0.3;
                    ctx.fillStyle = `rgba(56, 189, 248, ${pulse * p.alpha})`;
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, 1.8 * (r / rows + 0.5), 0, Math.PI * 2);
                    ctx.fill();
                }
            }

            ctx.restore();
        }

        drawOrbitalCoordinates(ctx) {
            ctx.save();
            const cx = this.width * 0.5 + this.mouseX * 0.8;
            const cy = this.height * 0.36 + this.mouseY * 0.6;
            const radius = Math.min(this.width, this.height) * 0.18;

            ctx.translate(cx, cy);

            // Orbit Ring 1 (Electric Indigo, tilted)
            ctx.save();
            ctx.rotate(this.time * 0.15);
            ctx.scale(1, 0.36);
            ctx.strokeStyle = 'rgba(99, 102, 241, 0.22)';
            ctx.lineWidth = 1.3;
            ctx.setLineDash([8, 12]);
            ctx.beginPath();
            ctx.arc(0, 0, radius, 0, Math.PI * 2);
            ctx.stroke();

            // Satellite node on Ring 1
            const satX1 = Math.cos(this.time * 1.1) * radius;
            const satY1 = Math.sin(this.time * 1.1) * radius;
            ctx.fillStyle = '#818cf8';
            ctx.shadowColor = '#6366f1';
            ctx.shadowBlur = 10;
            ctx.beginPath();
            ctx.arc(satX1, satY1, 3.5, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();

            // Orbit Ring 2 (Frost Cyan, counter-rotated)
            ctx.save();
            ctx.rotate(-this.time * 0.1 + 0.8);
            ctx.scale(1, 0.42);
            ctx.strokeStyle = 'rgba(56, 189, 248, 0.18)';
            ctx.lineWidth = 1.1;
            ctx.setLineDash([4, 16]);
            ctx.beginPath();
            ctx.arc(0, 0, radius * 1.25, 0, Math.PI * 2);
            ctx.stroke();

            // Satellite node on Ring 2
            const satX2 = Math.cos(-this.time * 0.9) * (radius * 1.25);
            const satY2 = Math.sin(-this.time * 0.9) * (radius * 1.25);
            ctx.fillStyle = '#38bdf8';
            ctx.shadowColor = '#38bdf8';
            ctx.shadowBlur = 12;
            ctx.beginPath();
            ctx.arc(satX2, satY2, 3, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();

            // Subtle Crosshair Reticle in center
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
            ctx.lineWidth = 1;
            ctx.setLineDash([]);
            ctx.beginPath();
            ctx.moveTo(-16, 0); ctx.lineTo(16, 0);
            ctx.moveTo(0, -16); ctx.lineTo(0, 16);
            ctx.stroke();

            ctx.restore();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => new CyberDefenseGrid('cyber-3d-canvas'));
    } else {
        new CyberDefenseGrid('cyber-3d-canvas');
    }
})();

