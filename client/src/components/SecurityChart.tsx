import { useEffect, useRef } from "react";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface SecurityChartProps {
  type: "line" | "doughnut";
  title: string;
  data: any;
  options?: any;
}

export default function SecurityChart({ type, title, data, options }: SecurityChartProps) {
  const defaultOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { 
          color: 'hsl(var(--foreground))',
          font: { family: 'Inter' }
        }
      },
      title: {
        display: false,
      },
    },
    scales: type === "line" ? {
      y: {
        ticks: { color: 'hsl(var(--muted-foreground))' },
        grid: { color: 'hsl(var(--border))' }
      },
      x: {
        ticks: { color: 'hsl(var(--muted-foreground))' },
        grid: { color: 'hsl(var(--border))' }
      }
    } : undefined,
  };

  const chartOptions = { ...defaultOptions, ...options };

  const Chart = type === "line" ? Line : Doughnut;

  return (
    <div className="bg-card rounded-xl p-6 border border-border">
      <h3 className="text-lg font-semibold text-foreground mb-4">{title}</h3>
      <div className="h-64">
        <Chart data={data} options={chartOptions} />
      </div>
    </div>
  );
}
