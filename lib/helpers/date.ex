defmodule WebAuth.Helpers.Date do
  def diff_now(unix_timestamp, opts \\ [])

  def diff_now(unix_timestamp, opts) when is_number(unix_timestamp) do
    with unit <- Keyword.get(opts, :unit, :second),
         calendar <- Keyword.get(opts, :calendar, Calendar.ISO),
         {:ok, date_to_compare} <- DateTime.from_unix(unix_timestamp, unit, calendar) do
      diff_now(date_to_compare, opts)
    end
  end

  def diff_now(%DateTime{} = date_to_compare, opts) do
    with unit <- Keyword.get(opts, :unit, :second),
         {:ok, now_date} <- DateTime.now("Etc/UTC") do
      DateTime.diff(date_to_compare, now_date, unit)
    end
  end
end
