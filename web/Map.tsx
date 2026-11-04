import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { FeatureCollection } from "geojson";
import { Minus, Plus, RotateCcw, X } from "lucide-react";
import type { Node, PublicBanRow, PublicNode } from "./types";
import { NodeAddresses, nodeAddressLabel } from "./NodeAddresses";

const countries = feature(
  world as unknown as Topology,
  (world as unknown as Topology).objects.countries as GeometryCollection,
) as FeatureCollection;
type MapNode = PublicNode & Pick<Node, "name">;
type View = { zoom: number; pan: [number, number] };
type Marker = {
  key: string;
  point: [number, number];
  nodes: MapNode[];
  sources: PublicBanRow[];
};
const initialView: View = { zoom: 1, pan: [0, 0] };
const place = (g: PublicNode | PublicBanRow) =>
  [g.city, g.country].filter(Boolean).join(", ") || "未知位置";
const time = (value: number | null) =>
  value
    ? new Date(value * 1000).toLocaleString("zh-CN", { hour12: false })
    : "尚未同步";

export function WorldMap({
  nodes,
  bans,
  publicView = false,
  loading = false,
  error = "",
  onRetry,
}: {
  nodes: MapNode[];
  bans: PublicBanRow[];
  publicView?: boolean;
  loading?: boolean;
  error?: string;
  onRetry?: () => void;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const svg = useRef<SVGSVGElement>(null);
  const popup = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 1000, height: 490 });
  const [view, setView] = useState<View>(initialView);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [popupSize, setPopupSize] = useState({ width: 300, height: 240 });
  const drag = useRef<{
    id: number;
    x: number;
    y: number;
    point: DOMPoint;
    pan: [number, number];
    moved: boolean;
  } | null>(null);
  const suppressClick = useRef(false);
  const { width, height } = size;
  const center = { x: width / 2, y: height / 2 };
  useLayoutEffect(() => {
    const element = wrap.current!;
    const observer = new ResizeObserver(() => {
      const rect = element.getBoundingClientRect();
      setSize({
        width: Math.max(1, rect.width),
        height: Math.max(1, rect.height),
      });
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  const projection = useMemo(
    () =>
      geoNaturalEarth1().fitExtent(
        [
          [24, 55],
          [Math.max(25, width - 24), Math.max(56, height - 65)],
        ],
        { type: "Sphere" },
      ),
    [width, height],
  );
  const path = useMemo(() => geoPath(projection), [projection]);
  const nodeById = useMemo(
    () => new Map(nodes.map((node) => [node.id, node])),
    [nodes],
  );
  const { connections, markers } = useMemo(() => {
    const point = (g: PublicNode | PublicBanRow) =>
      g.latitude != null &&
      g.longitude != null &&
      Number.isFinite(g.latitude) &&
      Number.isFinite(g.longitude)
        ? projection([g.longitude, g.latitude])
        : null;
    const groups = new Map<string, Marker>();
    const group = (g: PublicNode | PublicBanRow) => {
      const p = point(g);
      if (!p) return null;
      const key = `${g.longitude},${g.latitude}`;
      let marker = groups.get(key);
      if (!marker) {
        marker = { key, point: p, nodes: [], sources: [] };
        groups.set(key, marker);
      }
      return marker;
    };
    nodes.forEach((node) => group(node)?.nodes.push(node));
    const seen = new Set<string>();
    const sourceLocations = new Set<string>();
    const sourceRows = new Map<string, PublicBanRow>();
    const connections: { key: string; d: string }[] = [];
    bans.forEach((ban) => {
      const from = point(ban);
      if (!from) return;
      const location = `${ban.longitude},${ban.latitude}`;
      if (!sourceLocations.has(location) && sourceLocations.size >= 200) return;
      sourceLocations.add(location);
      // Different services can describe the same visible source and target.
      const rowKey = `${location}|${ban.ip}|${ban.node_id}`;
      const previous = sourceRows.get(rowKey);
      if (!previous || previous.observed_at < ban.observed_at)
        sourceRows.set(rowKey, ban);
      const node = nodeById.get(ban.node_id);
      const to = node ? point(node) : null;
      const key = `${location}|${ban.node_id}`;
      if (!to || seen.has(key) || seen.size >= 200) return;
      seen.add(key);
      const [x, y] = from,
        [tx, ty] = to;
      connections.push({
        key,
        d: `M${x},${y} Q${(x + tx) / 2},${Math.min(y, ty) - Math.min(100, Math.abs(x - tx) * 0.18) - 18} ${tx},${ty}`,
      });
    });
    sourceRows.forEach((ban) => group(ban)?.sources.push(ban));
    return { connections, markers: [...groups.values()] };
  }, [nodes, bans, nodeById, projection]);
  const selected = markers.find((marker) => marker.key === selectedKey);
  useEffect(() => {
    if (selectedKey && !selected) setSelectedKey(null);
  }, [selectedKey, selected]);
  useEffect(() => {
    if (!selectedKey) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSelectedKey(null);
    };
    const outside = (event: PointerEvent) => {
      if (!wrap.current?.contains(event.target as globalThis.Node))
        setSelectedKey(null);
    };
    document.addEventListener("keydown", close);
    document.addEventListener("pointerdown", outside);
    return () => {
      document.removeEventListener("keydown", close);
      document.removeEventListener("pointerdown", outside);
    };
  }, [selectedKey]);
  useLayoutEffect(() => {
    const element = popup.current;
    if (!element) return;
    const observer = new ResizeObserver(() => {
      setPopupSize({
        width: element.offsetWidth,
        height: element.offsetHeight,
      });
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, [selectedKey, selected]);

  // Use the SVG matrix, including viewBox offsets, for all pointer coordinates.
  const localPoint = (clientX: number, clientY: number) => {
    const matrix = svg.current?.getScreenCTM();
    return matrix
      ? new DOMPoint(clientX, clientY).matrixTransform(matrix.inverse())
      : null;
  };
  const zoomAt = (
    zoom: number | ((previous: number) => number),
    anchor = center,
  ) => {
    setView((previous) => {
      const next = Math.max(
        1,
        Math.min(5, typeof zoom === "function" ? zoom(previous.zoom) : zoom),
      );
      const ratio = next / previous.zoom;
      return {
        zoom: next,
        pan: [
          anchor.x - center.x - (anchor.x - center.x - previous.pan[0]) * ratio,
          anchor.y - center.y - (anchor.y - center.y - previous.pan[1]) * ratio,
        ],
      };
    });
  };
  useEffect(() => {
    const element = svg.current!;
    const wheel = (event: WheelEvent) => {
      event.preventDefault();
      drag.current = null;
      const anchor = localPoint(event.clientX, event.clientY);
      if (!anchor) return;
      const delta =
        event.deltaY *
        (event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? height : 1);
      zoomAt(
        (previous) =>
          previous *
          Math.exp(
            -Math.max(-150, Math.min(150, delta)) *
              (event.ctrlKey ? 0.01 : 0.002),
          ),
        anchor,
      );
    };
    element.addEventListener("wheel", wheel, { passive: false });
    return () => element.removeEventListener("wheel", wheel);
  }, [width, height]);

  const anchor = selected
    ? {
        x: center.x + view.pan[0] + (selected.point[0] - center.x) * view.zoom,
        y: center.y + view.pan[1] + (selected.point[1] - center.y) * view.zoom,
      }
    : null;
  const popupPosition = anchor
    ? {
        left: Math.max(
          10,
          Math.min(width - popupSize.width - 10, anchor.x + 16),
        ),
        top: Math.max(
          48,
          Math.min(
            height - popupSize.height - 48,
            anchor.y - popupSize.height / 2,
          ),
        ),
      }
    : undefined;
  return (
    <div className="map-wrap" ref={wrap}>
      <div className="map-caption">
        <span className="live-dot" /> 全球防护网络{" "}
        <span className="muted">/ WORLD VIEW</span>
      </div>
      <svg
        ref={svg}
        className="world-map"
        viewBox={`0 0 ${width} ${height}`}
        role="group"
        aria-label="世界封禁来源与节点连线地图"
        onPointerDown={(event) => {
          if (event.button !== 0 || !event.isPrimary) return;
          const point = localPoint(event.clientX, event.clientY);
          if (!point) return;
          suppressClick.current = false;
          drag.current = {
            id: event.pointerId,
            x: event.clientX,
            y: event.clientY,
            point,
            pan: [...view.pan],
            moved: false,
          };
        }}
        onPointerMove={(event) => {
          const current = drag.current;
          if (!current || current.id !== event.pointerId) return;
          const point = localPoint(event.clientX, event.clientY);
          if (!point) return;
          if (
            !current.moved &&
            Math.hypot(event.clientX - current.x, event.clientY - current.y) > 4
          ) {
            current.moved = true;
            suppressClick.current = true;
            event.currentTarget.setPointerCapture(event.pointerId);
          }
          if (current.moved)
            setView((previous) => ({
              ...previous,
              pan: [
                current.pan[0] + point.x - current.point.x,
                current.pan[1] + point.y - current.point.y,
              ],
            }));
        }}
        onPointerUp={() => {
          drag.current = null;
        }}
        onPointerCancel={() => {
          drag.current = null;
          suppressClick.current = true;
        }}
        onLostPointerCapture={() => {
          drag.current = null;
        }}
        onClick={() => {
          if (!suppressClick.current) setSelectedKey(null);
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
        </defs>
        <rect width={width} height={height} fill="url(#sea)" />
        <rect width={width} height={height} fill="url(#grid)" opacity=".65" />
        <g
          className="map-geography"
          transform={`translate(${center.x + view.pan[0]},${center.y + view.pan[1]}) scale(${view.zoom}) translate(${-center.x},${-center.y})`}
        >
          {countries.features.map((country, i) => (
            <path key={i} d={path(country) ?? ""} className="country" />
          ))}
          {connections.map(({ key, d }, i) => (
            <g key={key} className="map-connection">
              <path d={d} className="connection" />
              <circle r="2" fill="#f5a65b">
                <animateMotion
                  dur={`${3 + (i % 4)}s`}
                  repeatCount="indefinite"
                  path={d}
                />
              </circle>
            </g>
          ))}
          {markers.map((marker) => {
            const isNode = marker.nodes.length > 0;
            const label = [
              ...marker.nodes.map(
                (node) =>
                  `受保护节点 ${!publicView && node.name ? node.name : nodeAddressLabel(node)}`,
              ),
              ...marker.sources.map((ban) => `封禁来源 ${ban.ip}`),
            ].join("；");
            return (
              <g
                key={marker.key}
                className={`map-marker ${selectedKey === marker.key ? "selected" : ""}`}
                transform={`translate(${marker.point[0]},${marker.point[1]}) scale(${1 / view.zoom})`}
                role="button"
                tabIndex={0}
                aria-label={label}
                aria-expanded={selectedKey === marker.key}
                onClick={(event) => {
                  event.stopPropagation();
                  if (!suppressClick.current) setSelectedKey(marker.key);
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    setSelectedKey(marker.key);
                  }
                }}
              >
                <circle r="14" className="marker-hit" />
                {isNode && <circle r="11" className="node-halo" />}
                <circle
                  r={isNode ? 4 : 3}
                  className={isNode ? "node-dot" : "source-dot"}
                  fill={
                    isNode
                      ? marker.nodes.some((node) => node.online)
                        ? "#72e8be"
                        : "#82919f"
                      : undefined
                  }
                />
              </g>
            );
          })}
        </g>
      </svg>
      {selected && (
        <div
          ref={popup}
          className="map-popup"
          role="dialog"
          aria-label="地图节点信息"
          style={popupPosition}
        >
          <div className="map-popup-heading">
            <strong>节点信息</strong>
            <button
              aria-label="关闭节点信息"
              onClick={() => setSelectedKey(null)}
            >
              <X size={15} />
            </button>
          </div>
          <div className="map-popup-content">
            {selected.nodes.map((node) => (
              <div className="map-popup-item" key={node.id}>
                <strong>
                  受保护节点{!publicView && node.name ? ` · ${node.name}` : ""}
                </strong>
                <NodeAddresses node={node} />
                <span>{place(node)}</span>
                <span className={node.online ? "map-online" : "muted"}>
                  {node.online ? "在线" : "离线 · 最后已知状态"}
                </span>
                <small>最近上报：{time(node.last_seen)}</small>
              </div>
            ))}
            {selected.sources.map((ban) => {
              const node = nodeById.get(ban.node_id);
              return (
                <div
                  className="map-popup-item"
                  key={`${ban.ip}|${ban.node_id}`}
                >
                  <strong>封禁来源</strong>
                  <code>{ban.ip}</code>
                  <span>{place(ban)}</span>
                  <small>目标节点</small>
                  {!publicView && node?.name && <span>{node.name}</span>}
                  <NodeAddresses node={node} />
                  <small>观测时间：{time(ban.observed_at)}</small>
                </div>
              );
            })}
          </div>
        </div>
      )}
      {error ? (
        <div className="map-notice" role="alert">
          {error}
          <button onClick={onRetry}>重试</button>
        </div>
      ) : loading ? (
        <div className="map-notice" role="status">
          正在连接防护网络…
        </div>
      ) : (
        !connections.length && (
          <div className="map-empty">
            <span className="radar-ring" />
            <p>
              {bans.length ? "等待具有地理坐标的封禁记录" : "防护网络已就绪"}
            </p>
            <small>
              {bans.length
                ? "暂无可绘制的来源与节点连线"
                : "节点产生封禁记录后，将在这里显示来源与连线"}
            </small>
          </div>
        )
      )}
      <div className="map-bottom">
        <span>
          <i className="legend-source" />
          封禁来源 <i className="legend-node" />
          受保护节点
        </span>
        {publicView && (
          <a
            className="map-attribution"
            href="https://db-ip.com"
            target="_blank"
            rel="noreferrer"
          >
            IP Geolocation by DB-IP
          </a>
        )}
        <span className="map-controls">
          <button
            aria-label="放大地图"
            onClick={() => zoomAt((zoom) => zoom + 0.4)}
          >
            <Plus size={15} />
          </button>
          <button
            aria-label="缩小地图"
            onClick={() => zoomAt((zoom) => zoom - 0.4)}
          >
            <Minus size={15} />
          </button>
          <button aria-label="重置地图" onClick={() => setView(initialView)}>
            <RotateCcw size={14} />
          </button>
        </span>
      </div>
    </div>
  );
}
