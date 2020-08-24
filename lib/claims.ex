defmodule WebAuth.Claims do
  require Logger

  def validate(_claims, [], _client) do
    :ok
  end

  def validate(claims, [validation | rest], client) when is_map(claims) do
    with :ok <- validate(claims, validation, client) do
      validate(claims, rest, client)
    end
  end

  def validate(%{"exp" => expiration}, :exp, _client) do
    with {:ok, expiration_date} <- DateTime.from_unix(expiration, :second, Calendar.ISO),
         {:ok, current_date} <- DateTime.now("Etc/UTC") do
      Logger.debug("JWT expiration: #{expiration}, JWT date: #{expiration_date}, current date: #{current_date}")

      if DateTime.diff(expiration_date, current_date) > 0 do
        :ok
      else
        {:error, :expired}
      end
    end
  end

  def validate(%{"aud" => audience}, {:aud, target_audience}, client) do
    validate_audience(audience, target_audience, client)
  end

  defp validate_audience([audience | rest], target_audience, client) when is_binary(audience) and is_binary(target_audience) do
    if validate_audience(audience, target_audience, client) == :ok do
      :ok
    else
      validate_audience(rest, target_audience, client)
    end
  end

  defp validate_audience([], _target_audience, _client) do
    {:error, :no_audience_found}
  end

  defp validate_audience(audience, target_audience, _client) when is_binary(audience) and is_binary(target_audience) do
    if audience == target_audience do
      :ok
    else
      {:error, :invalid_audience}
    end
  end
end
