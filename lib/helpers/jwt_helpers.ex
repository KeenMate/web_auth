defmodule WebAuth.Helpers.JwtHelpers do
  def validate_claims(%{"exp" => exp, "aud" => aud}, valid_audience) when is_binary(valid_audience) do
    with true <- not_expired?(exp),
         true <- valid_audience?(aud, valid_audience) do
      :ok
    else
      _ -> :error
    end
  end

  defp not_expired?(expiration) when is_number(expiration) do
    {:ok, exp_date} = DateTime.from_unix(expiration, :second, Calendar.ISO)
    current_date = DateTime.now!("Etc/UTC")

    DateTime.diff(exp_date, current_date) > 0
  end

  defp valid_audience?(audience, valid_audience) when is_binary(audience) and is_binary(valid_audience) do
    audience == valid_audience
  end

  defp valid_audience?(audiences, valid_audience) when is_list(audiences) and is_binary(valid_audience) do
    Enum.any?(audiences, &(&1 == valid_audience))
  end
end
