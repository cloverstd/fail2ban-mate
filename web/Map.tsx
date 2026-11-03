import { useMemo, useRef, useState } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { FeatureCollection } from "geojson";
import { Minus, Plus, RotateCcw } from "lucide-react";
import type { BanRow, Node } from "./types";

const countries = feature(
  world as unknown as Topology,
  (world as unknown as Topology).objects.countries as GeometryCollection,
) as FeatureCollection;
const projection = geoNaturalEarth1().fitExtent(
  [
    [24, 25],
    [976, 465],
  ],
  { type: "Sphere" },
);
const path = geoPath(projection);
function point(g: { latitude?: number | null; longitude?: number | null }) {
  return g.latitude != null && g.longitude != null
    ? projection([g.longitude, g.latitude])
    : null;
}
export function WorldMap({ nodes, bans }: { nodes: Node[]; bans: BanRow[] }) {
  const [zoom, setZoom] = useState(1),
    [pan, setPan] = useState([0, 0]);
  const drag = useRef<{ x: number; y: number; pan: number[] } | null>(null);
  const connections = useMemo(() => {
    const seen = new Set<string>();
    return bans.flatMap((b) => {
      const n = nodes.find((n) => n.id === b.node_id);
      const from = point(b),
        to = n ? point(n) : null;
      const key = `${b.longitude},${b.latitude},${b.node_id}`;
      if (!from || !to || seen.has(key) || seen.size >= 200) return [];
      seen.add(key);
      const [x, y] = from,
        [tx, ty] = to;
      const d = `M${x},${y} Q${(x + tx) / 2},${Math.min(y, ty) - Math.min(100, Math.abs(x - tx) * 0.18) - 18} ${tx},${ty}`;
      return [{ b, n: n!, from, to, d }];
    });
  }, [nodes, bans]);
  return (
    <div className="map-wrap">
      <div className="map-caption">
        <span className="live-dot" /> 全球防护网络{" "}
        <span className="muted">/ WORLD VIEW</span>
      </div>
      <svg
        className="world-map"
        viewBox="0 0 1000 490"
        role="img"
        aria-label="世界封禁来源与节点连线地图"
        onPointerDown={(e) => {
          drag.current = { x: e.clientX, y: e.clientY, pan: [...pan] };
          e.currentTarget.setPointerCapture(e.pointerId);
        }}
        onPointerMove={(e) => {
          if (drag.current) {
            const factor = 1000 / e.currentTarget.getBoundingClientRect().width;
            setPan([
              drag.current.pan[0] + (e.clientX - drag.current.x) * factor,
              drag.current.pan[1] + (e.clientY - drag.current.y) * factor,
            ]);
          }
        }}
        onPointerUp={() => {
          drag.current = null;
        }}
        onPointerCancel={() => {
          drag.current = null;
        }}
      >
        <defs>
          <pattern
            id="grid"
            width="25"
            height="25"
            patternUnits="userSpaceOnUse"
          >
            <path
              d="M25 0H0V25"
              fill="none"
              stroke="#19232d"
              strokeWidth=".5"
            />
          </pattern>
          <radialGradient id="sea">
            <stop stopColor="#10222e" />
            <stop offset="1" stopColor="#0d141b" />
          </radialGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" />
          </filter>
        </defs>
        <rect width="1000" height="490" fill="url(#sea)" />
        <rect width="1000" height="490" fill="url(#grid)" opacity=".65" />
        <g
          transform={`translate(${500 + pan[0]},${245 + pan[1]}) scale(${zoom}) translate(-500,-245)`}
        >
          {countries.features.map((c, i) => (
            <path key={i} d={path(c) ?? ""} className="country" />
          ))}
          {connections.map(({ b, n, from, d }, i) => (
            <g key={i}>
              <path d={d} className="connection" />
              <circle r="2" fill="#f5a65b">
                <animateMotion
                  dur={`${3 + (i % 4)}s`}
                  repeatCount="indefinite"
                  path={d}
                />
              </circle>
              <circle cx={from[0]} cy={from[1]} r="3" className="source-dot">
                <title>
                  {b.ip} · {b.city || b.country || "未知位置"} →{" "}
                  {n.name || n.ip}
                </title>
              </circle>
            </g>
          ))}
          {nodes.map((n) => {
            const p = point(n);
            return p ? (
              <g key={n.id}>
                <circle cx={p[0]} cy={p[1]} r="11" className="node-halo" />
                <circle
                  cx={p[0]}
                  cy={p[1]}
                  r="4"
                  fill={n.online ? "#72e8be" : "#82919f"}
                  stroke="#0d141b"
                  strokeWidth="1.5"
                >
                  <title>
                    {n.name || n.ip} · {n.city || n.country || "未知位置"} ·{" "}
                    {n.online ? "在线" : "离线"}
                  </title>
                </circle>
              </g>
            ) : null;
          })}
        </g>
      </svg>
      {!connections.length && (
        <div className="map-empty">
          <span className="radar-ring" />
          <p>{bans.length ? "等待具有地理坐标的封禁记录" : "防护网络已就绪"}</p>
          <small>
            {bans.length
              ? "未知位置的 IP 仍显示在下方列表"
              : "节点产生封禁记录后，将在这里显示来源与连线"}
          </small>
        </div>
      )}
      <div className="map-bottom">
        <span>
          <i className="legend-source" />
          封禁来源 <i className="legend-node" />
          受保护节点
        </span>
        <span className="map-controls">
          <button
            aria-label="放大地图"
            onClick={() => setZoom((z) => Math.min(5, z + 0.4))}
          >
            <Plus size={15} />
          </button>
          <button
            aria-label="缩小地图"
            onClick={() => setZoom((z) => Math.max(1, z - 0.4))}
          >
            <Minus size={15} />
          </button>
          <button
            aria-label="重置地图"
            onClick={() => {
              setZoom(1);
              setPan([0, 0]);
            }}
          >
            <RotateCcw size={14} />
          </button>
        </span>
      </div>
    </div>
  );
}
