/**
 * Avatar - Composant React 3D réutilisable pour afficher le personnage Avatar
 *          et déclencher ses animations à la demande.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * INSTALLATION
 * ─────────────────────────────────────────────────────────────────────────────
 *   npm install three @react-three/fiber @react-three/drei
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SETUP
 * ─────────────────────────────────────────────────────────────────────────────
 *   1. Place ton fichier .glb dans le dossier `public/` de ton projet.
 *      (Next.js, Vite, CRA, Remix : tous servent /public à la racine.)
 *   2. Si tu veux le servir depuis un autre chemin, change la constante
 *      MODEL_URL juste en dessous.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * UTILISATION
 * ─────────────────────────────────────────────────────────────────────────────
 *   import { AvatarViewer } from './Avatar'
 *
 *   function ResultScreen({ result }) {
 *     const animationMap = {
 *       win:       'Celebrate',
 *       lose:      'Defeated',
 *       greeting:  'Waving',
 *     }
 *     return (
 *       <div style={{ width: 400, height: 500 }}>
 *         <AvatarViewer animation={animationMap[result]} />
 *       </div>
 *     )
 *   }
 *
 *   Animations actuellement disponibles dans Avatar.glb :
 *     'Waving' | 'Defeated' | 'Celebrate'
 *   (Si tu rajoutes des animations dans Blender, elles seront automatiquement
 *   accessibles ici via leur nom de NLA Track.)
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { Suspense, useEffect, useRef, useMemo } from 'react'
import * as THREE from 'three'
import { Canvas } from '@react-three/fiber'
import {
  useGLTF,
  useAnimations,
  OrbitControls,
  Environment,
} from '@react-three/drei'
import { SkeletonUtils } from 'three-stdlib'

const MODEL_URL = '/AvatarQuizzos.glb'

/**
 * AvatarModel
 * ───────────
 * Le mesh + ses animations, sans Canvas autour.
 * À utiliser si tu veux l'intégrer dans ta propre scène 3D (ex. plusieurs
 * objets dans le même Canvas, post-processing custom, etc.).
 *
 * Props :
 *   animation : string  — nom du clip d'animation à jouer
 *   color     : string  — couleur du modèle (ex. '#ff6b6b')
 *   ...props            — passées au <primitive> (position, rotation, scale...)
 */
export function AvatarModel({ animation = 'Waving', color, ...props }) {
  const group = useRef()
  const { scene, animations } = useGLTF(MODEL_URL)
  const { actions } = useAnimations(animations, group)

    // Clone la scène + matériaux pour que cette instance soit indépendante
    const clonedScene = useMemo(() => {
    const clone = SkeletonUtils.clone(scene)
    clone.traverse((child) => {
        if (child.isMesh && child.material) {
        child.material = Array.isArray(child.material)
            ? child.material.map((m) => m.clone())
            : child.material.clone()
        }
    })
    return clone
    }, [scene])

    // Applique la couleur dynamiquement
  useEffect(() => {
    if (!color) return
    clonedScene.traverse((child) => {
      if (child.isMesh && child.material && 'color' in child.material) {
        child.material.color.set(color)
      }
    })
  }, [color, clonedScene])

  useEffect(() => {
    const next = actions[animation]
    if (!next) {
      console.warn(
        `[Avatar] Animation "${animation}" introuvable. Disponibles :`,
        Object.keys(actions),
      )
      return
    }

    // Crossfade : les autres clips s'estompent, le nouveau s'enchaîne en douceur
    Object.values(actions).forEach((a) => {
      if (a !== next && a.isRunning()) a.fadeOut(0.3)
    })
    next.reset().fadeIn(0.3).play()

    return () => {
      next.fadeOut(0.3)
    }
  }, [animation, actions])

  return <primitive ref={group} object={clonedScene} {...props} />
}

// Précharge le .glb dès que ce module est importé. La 1re instance du composant
// s'affichera donc instantanément au lieu de provoquer un chargement.
useGLTF.preload(MODEL_URL)

/**
 * AvatarViewer
 * ────────────
 * Composant clé-en-main : Canvas, caméra, lumières et OrbitControls inclus.
 * Place-le dans un conteneur dimensionné (width/height non-zéro).
 *
 * Props :
 *   animation : string  — 'Waving' | 'Defeated' | 'Celebrate' (default 'Waving')
 *   controls  : bool    — affiche les OrbitControls (default true)
 *   className, style    — pour styler le <div> conteneur
 */
export function AvatarViewer({
  animation = 'Defeated',
  controls = false,
  color,
  className,
  style,
}) {
  return (
    <div
      className={className}
      style={{ width: '100%', height: '100%', ...style }}
    >
      <Canvas camera={{ position: [0, 1, 2.5], fov: 60 }} shadows>
        <ambientLight intensity={0.5} />
        <directionalLight
          position={[3, 5, 2]}
          intensity={1.6}
          castShadow
          shadow-mapSize={[1024, 1024]}
        />

        <Suspense fallback={null}>
          <AvatarModel animation={animation} color={color} position={[0, -1, 0]} />
          <Environment preset="city" />
        </Suspense>

        {controls && (
          <OrbitControls
            enablePan={false}
            minDistance={1.5}
            maxDistance={5}
            target={[0, 0, 0]}
          />
        )}
      </Canvas>
    </div>
  )
}
