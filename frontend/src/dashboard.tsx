import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";

import "./styles.css";

type DashboardStats = {
  failure: number;
  safe: number;
  suspicious: number;
  inconclusive: number;
  dangerous: number;
};

type DashboardResponse = {
  labels: string[];
  data: number[];
  new_users: number;
  total_reporters: number;
  total_cases: number;
  stats: DashboardStats;
};

type DashboardRootDataset = {
  month: string;
  year: string;
};

const parseDataset = (element: HTMLElement): DashboardRootDataset | null => {
  const { month, year } = element.dataset;
  if (!month || !year) {
    return null;
  }
  return { month, year };
};

const fetchDashboard = async (month: string, year: string) => {
  const response = await fetch(`/dashboard-change/${month}/${year}`);
  if (!response.ok) {
    throw new Error("Failed to load dashboard");
  }
  return (await response.json()) as DashboardResponse;
};

const DashboardApp = ({ month, year }: { month: string; year: string }) => {
  const [currentMonth, setCurrentMonth] = useState(month);
  const [currentYear, setCurrentYear] = useState(year);
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setError(null);
    fetchDashboard(currentMonth, currentYear)
      .then((payload) => {
        if (active) {
          setData(payload);
        }
      })
      .catch((err: Error) => {
        if (active) {
          setError(err.message);
        }
      });

    return () => {
      active = false;
    };
  }, [currentMonth, currentYear]);

  const summary = useMemo(() => {
    if (!data) {
      return [];
    }
    return [
      { label: "New Users", value: data.new_users },
      { label: "Total Reporters", value: data.total_reporters },
      { label: "Total Submissions", value: data.total_cases }
    ];
  }, [data]);

  return (
    <section className="dashboard">
      <header className="dashboard__header">
        <h1>Monthly Dashboard</h1>
        <p>
          Dashboard for {currentMonth}/{currentYear}
        </p>
      </header>

      <form
        className="dashboard__controls"
        onSubmit={(event) => event.preventDefault()}
      >
        <label>
          Month
          <select
            value={currentMonth}
            onChange={(event) => setCurrentMonth(event.target.value)}
          >
            {Array.from({ length: 12 }, (_, index) => {
              const value = String(index + 1);
              return (
                <option key={value} value={value}>
                  {value}
                </option>
              );
            })}
          </select>
        </label>
        <label>
          Year
          <select
            value={currentYear}
            onChange={(event) => setCurrentYear(event.target.value)}
          >
            {Array.from({ length: 5 }, (_, index) => {
              const value = String(2022 + index);
              return (
                <option key={value} value={value}>
                  {value}
                </option>
              );
            })}
          </select>
        </label>
      </form>

      {error ? <p className="dashboard__error">{error}</p> : null}

      <div className="dashboard__summary">
        {summary.map((item) => (
          <div key={item.label} className="dashboard__card">
            <h2>{item.label}</h2>
            <p>{data ? item.value : "–"}</p>
          </div>
        ))}
      </div>

      <div className="dashboard__stats">
        <h2>Case Distribution</h2>
        <ul>
          <li>Failure: {data?.stats.failure ?? "–"}</li>
          <li>Safe: {data?.stats.safe ?? "–"}</li>
          <li>Suspicious: {data?.stats.suspicious ?? "–"}</li>
          <li>Inconclusive: {data?.stats.inconclusive ?? "–"}</li>
          <li>Dangerous: {data?.stats.dangerous ?? "–"}</li>
        </ul>
      </div>
    </section>
  );
};

const root = document.getElementById("dashboard-root");
if (root) {
  const dataset = parseDataset(root);
  if (dataset) {
    createRoot(root).render(
      <DashboardApp month={dataset.month} year={dataset.year} />
    );
  }
}
